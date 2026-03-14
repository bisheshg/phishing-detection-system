#!/usr/bin/env python3
"""
Investigate Data Leakage - Find what's making boosting models too perfect
"""

import numpy as np
import pandas as pd
import pickle
import warnings
warnings.filterwarnings('ignore')

print("="*70)
print("DATA LEAKAGE INVESTIGATION")
print("="*70)

# Load the model bundle
print("\n1. Loading trained models...")
with open('models/phishing_model_bundle_REALISTIC_v3.pkl', 'rb') as f:
    bundle = pickle.load(f)

lgb_model = bundle['gradient_boosting']
feature_names = bundle['feature_names']

print(f"   Features: {len(feature_names)}")

# Get feature importances
print("\n2. Analyzing feature importances...")
importances = pd.DataFrame({
    'feature': feature_names,
    'importance': lgb_model.feature_importances_
}).sort_values('importance', ascending=False)

print("\n   Top 20 Most Important Features:")
print("   " + "="*66)
for i, row in importances.head(20).iterrows():
    print(f"   {row['feature']:35s} : {row['importance']:8.0f} ({row['importance']/importances['importance'].sum()*100:5.1f}%)")

# Check for suspicious patterns
print("\n3. Checking for data leakage indicators...")

suspicious_features = []
total_importance = importances['importance'].sum()

# Check if any single feature dominates (>30% importance)
for _, row in importances.head(10).iterrows():
    pct = row['importance'] / total_importance * 100
    if pct > 30:
        suspicious_features.append({
            'feature': row['feature'],
            'importance_pct': pct,
            'reason': 'Single feature dominates (>30%)'
        })

print(f"\n   Suspicious features found: {len(suspicious_features)}")
if suspicious_features:
    for sf in suspicious_features:
        print(f"   ⚠️  {sf['feature']}: {sf['importance_pct']:.1f}% - {sf['reason']}")

# Load data to check correlations
print("\n4. Loading dataset to check feature-label correlations...")
df = pd.read_csv('phishurl.csv')

# Drop columns
DROP_COLS = ['FILENAME', 'URL', 'Domain', 'TLD', 'Title', 'URLSimilarityIndex']
df_clean = df.drop(columns=DROP_COLS, errors='ignore')

# Add engineered features (simplified version)
df_clean['ObfuscationIPRisk'] = df_clean['IsDomainIP'] * df_clean['HasObfuscation']
df_clean['InsecurePasswordField'] = (1 - df_clean['IsHTTPS']) * df_clean['HasPasswordField']
df_clean['PageCompletenessRatio'] = df_clean['NoOfSelfRef'] / (df_clean['NoOfExternalRef'] + 1)
df_clean['LegitContentScore'] = (
    df_clean['HasTitle'] + df_clean['HasFavicon'] +
    df_clean['HasDescription'] + df_clean['HasCopyrightInfo'] +
    df_clean['IsResponsive']
)
df_clean['SuspiciousFinancialFlag'] = (
    (df_clean['Bank'] + df_clean['Pay'] + df_clean['Crypto']) *
    (1 - df_clean['HasCopyrightInfo'])
)
df_clean['TitleMatchCombined'] = np.sqrt(
    df_clean['DomainTitleMatchScore'] * df_clean['URLTitleMatchScore']
)

# Calculate correlations for top features
print("\n5. Feature-Label Correlations (Top 15 important features):")
print("   " + "="*66)

for _, row in importances.head(15).iterrows():
    feat = row['feature']
    if feat in df_clean.columns:
        corr = df_clean[feat].corr(df_clean['label'])

        # Check if correlation is suspiciously high
        status = ""
        if abs(corr) > 0.8:
            status = " ⚠️ VERY HIGH CORRELATION!"
        elif abs(corr) > 0.6:
            status = " ⚠️ High correlation"

        print(f"   {feat:35s} : {corr:6.3f}{status}")

# Check for perfect separation
print("\n6. Checking for perfect separation features...")
print("   (Features that can perfectly predict the label)")

for _, row in importances.head(10).iterrows():
    feat = row['feature']
    if feat in df_clean.columns:
        # Check if any value of this feature has 100% correlation with label
        value_counts = df_clean.groupby(feat)['label'].agg(['mean', 'count'])

        # Find values that are 100% phishing (mean=0) or 100% legitimate (mean=1)
        perfect_phish = value_counts[value_counts['mean'] == 0]
        perfect_legit = value_counts[value_counts['mean'] == 1]

        if len(perfect_phish) > 0 or len(perfect_legit) > 0:
            total_perfect = (perfect_phish['count'].sum() if len(perfect_phish) > 0 else 0) + \
                          (perfect_legit['count'].sum() if len(perfect_legit) > 0 else 0)
            pct = total_perfect / len(df_clean) * 100

            if pct > 5:  # If >5% of data can be perfectly classified
                print(f"\n   ⚠️  {feat}:")
                print(f"       {pct:.1f}% of samples can be perfectly classified")
                if len(perfect_phish) > 0:
                    print(f"       {len(perfect_phish)} value(s) = 100% phishing")
                if len(perfect_legit) > 0:
                    print(f"       {len(perfect_legit)} value(s) = 100% legitimate")

# Recommendation
print("\n" + "="*70)
print("INVESTIGATION SUMMARY")
print("="*70)

# Calculate cumulative importance
cumsum = importances['importance'].cumsum() / importances['importance'].sum() * 100
top_5_pct = cumsum.iloc[4]
top_10_pct = cumsum.iloc[9]

print(f"\nFeature Concentration:")
print(f"  Top 5 features:  {top_5_pct:.1f}% of total importance")
print(f"  Top 10 features: {top_10_pct:.1f}% of total importance")

if top_5_pct > 70:
    print(f"\n  ⚠️  WARNING: Top 5 features account for {top_5_pct:.1f}% of importance")
    print(f"      This suggests the model relies heavily on a few features")
    print(f"      Possible data leakage or overfitting")

print("\nRECOMMENDATIONS:")
print("  1. Review top 10 features for potential leakage")
print("  2. Consider removing features with >80% correlation")
print("  3. Use Random Forest (99.97%) which shows more realistic errors")
print("  4. Test models on external dataset for validation")

print("\n" + "="*70)
