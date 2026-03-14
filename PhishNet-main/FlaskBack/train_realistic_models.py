#!/usr/bin/env python3
"""
Realistic Phishing Detection Model Training
Fixes data leakage by properly removing URLSimilarityIndex
Trains 4 models: LightGBM, XGBoost, CatBoost, Random Forest
"""

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import warnings
import os
import pickle
from datetime import datetime

warnings.filterwarnings('ignore')

# Sklearn
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import RobustScaler
from sklearn.metrics import (
    accuracy_score, f1_score, recall_score, precision_score,
    confusion_matrix, balanced_accuracy_score, roc_auc_score
)
from sklearn.ensemble import RandomForestClassifier

# Boosting models
import lightgbm as lgb
import xgboost as xgb
from catboost import CatBoostClassifier

print("="*70)
print("REALISTIC PHISHING DETECTION - MODEL TRAINING")
print("="*70)
print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print()

# ============================================================================
# 1. LOAD DATA
# ============================================================================
print("1. Loading dataset...")
df = pd.read_csv('phishurl.csv')
print(f"   Initial shape: {df.shape}")
print(f"   Columns: {len(df.columns)}")
print(f"   URLSimilarityIndex present: {'URLSimilarityIndex' in df.columns}")

# ============================================================================
# 2. CRITICAL: REMOVE DATA LEAKAGE
# ============================================================================
print("\n2. Removing data leakage features...")
DROP_COLS = ['FILENAME', 'URL', 'Domain', 'TLD', 'Title', 'URLSimilarityIndex']
print(f"   Dropping: {DROP_COLS}")

df_clean = df.drop(columns=DROP_COLS, errors='ignore')

# VERIFICATION
if 'URLSimilarityIndex' in df_clean.columns:
    raise ValueError("❌ CRITICAL ERROR: URLSimilarityIndex still present!")
else:
    print("   ✅ URLSimilarityIndex successfully removed")

print(f"   New shape: {df_clean.shape}")
print(f"   Features remaining: {df_clean.shape[1] - 1} (excluding label)")

# ============================================================================
# 3. PREPROCESSING
# ============================================================================
print("\n3. Preprocessing...")

# Outlier capping
HEAVY_TAILED = [
    'LineOfCode', 'LargestLineLength', 'NoOfExternalRef',
    'NoOfSelfRef', 'NoOfCSS', 'NoOfJS', 'NoOfImage',
    'NoOfEmptyRef', 'URLLength'
]
for col in HEAVY_TAILED:
    if col in df_clean.columns:
        cap_val = df_clean[col].quantile(0.995)
        df_clean[col] = df_clean[col].clip(upper=cap_val)
print("   ✅ Outliers capped at 99.5th percentile")

# ============================================================================
# 4. FEATURE ENGINEERING
# ============================================================================
print("\n4. Feature engineering...")

# Interaction features
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

# Drop redundant features
df_clean.drop(columns=['NoOfLettersInURL', 'URLTitleMatchScore'], inplace=True, errors='ignore')

# Log transforms
LOG_COLS = [
    'LineOfCode', 'LargestLineLength', 'NoOfExternalRef',
    'NoOfSelfRef', 'NoOfCSS', 'NoOfJS', 'NoOfImage',
    'NoOfEmptyRef', 'URLLength', 'DomainLength'
]
for col in LOG_COLS:
    if col in df_clean.columns:
        df_clean[f'{col}_log'] = np.log1p(df_clean[col])

print(f"   ✅ Total features: {len(df_clean.columns) - 1}")

# Final verification
assert 'URLSimilarityIndex' not in df_clean.columns, "URLSimilarityIndex still present!"
print("   ✅ Data leakage verification passed")

# ============================================================================
# 5. TRAIN/TEST SPLIT
# ============================================================================
print("\n5. Train/test split...")
X = df_clean.drop(columns=['label'])
y = df_clean['label']
FEATURE_NAMES = list(X.columns)

print(f"   Feature count: {len(FEATURE_NAMES)}")
print(f"   Sample count: {len(X)}")

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.20, random_state=42, stratify=y
)

# Scale
scaler = RobustScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

print(f"   Training: {X_train.shape}")
print(f"   Test: {X_test.shape}")

# Validation split for early stopping
X_tr, X_val, y_tr, y_val = train_test_split(
    X_train_scaled, y_train, test_size=0.15, stratify=y_train, random_state=42
)

# ============================================================================
# 6. TRAIN MODELS
# ============================================================================
print("\n6. Training models...")
print("   This will take 5-10 minutes...")

models = {}

# 6.1 LightGBM
print("\n   6.1 Training LightGBM...")
lgb_model = lgb.LGBMClassifier(
    objective='binary',
    n_estimators=500,
    learning_rate=0.05,
    num_leaves=63,
    max_depth=10,
    min_child_samples=30,
    subsample=0.8,
    colsample_bytree=0.8,
    reg_alpha=0.1,
    reg_lambda=0.1,
    class_weight='balanced',
    random_state=42,
    n_jobs=-1,
    verbose=-1
)
lgb_model.fit(
    X_tr, y_tr,
    eval_set=[(X_val, y_val)],
    callbacks=[lgb.early_stopping(50, verbose=False)]
)
models['gradient_boosting'] = lgb_model
print(f"       ✅ LightGBM trained (iterations: {lgb_model.best_iteration_})")

# 6.2 XGBoost (ADDED for better ensemble)
print("\n   6.2 Training XGBoost...")
n_legit = (y_train == 0).sum()
n_phish = (y_train == 1).sum()
scale_pos_weight = n_legit / n_phish

xgb_model = xgb.XGBClassifier(
    n_estimators=500,
    max_depth=6,
    learning_rate=0.05,
    subsample=0.8,
    colsample_bytree=0.8,
    min_child_weight=3,
    gamma=0.1,
    reg_alpha=0.1,
    reg_lambda=1.0,
    scale_pos_weight=scale_pos_weight,
    eval_metric="auc",
    early_stopping_rounds=50,
    tree_method="hist",
    random_state=42,
    n_jobs=-1
)
xgb_model.fit(
    X_tr, y_tr,
    eval_set=[(X_val, y_val)],
    verbose=False
)
models['xgboost'] = xgb_model
print(f"       ✅ XGBoost trained (iterations: {xgb_model.best_iteration})")

# 6.3 CatBoost (KEPT as requested)
print("\n   6.3 Training CatBoost...")
cat_model = CatBoostClassifier(
    iterations=500,
    learning_rate=0.05,
    depth=6,
    l2_leaf_reg=3,
    border_count=128,
    auto_class_weights='Balanced',
    eval_metric='AUC',
    random_seed=42,
    verbose=0,
    early_stopping_rounds=50,
    task_type='CPU'
)
cat_model.fit(
    X_tr, y_tr,
    eval_set=(X_val, y_val),
    use_best_model=True
)
models['catboost'] = cat_model
print(f"       ✅ CatBoost trained")

# 6.4 Random Forest
print("\n   6.4 Training Random Forest...")
rf_model = RandomForestClassifier(
    n_estimators=300,
    max_depth=20,
    min_samples_split=10,
    min_samples_leaf=5,
    max_features='sqrt',
    class_weight='balanced_subsample',
    oob_score=True,
    n_jobs=-1,
    random_state=42
)
rf_model.fit(X_train_scaled, y_train)
models['random_forest'] = rf_model
print(f"       ✅ Random Forest trained (OOB: {rf_model.oob_score_:.4f})")

# ============================================================================
# 7. EVALUATE MODELS
# ============================================================================
print("\n7. Evaluating models...")
print("="*70)

def evaluate(name, model, X_test, y_test):
    y_prob = model.predict_proba(X_test)[:, 1]
    y_pred = (y_prob >= 0.5).astype(int)
    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()

    acc = accuracy_score(y_test, y_pred)
    phish_recall = tp / (tp + fn)
    legit_recall = tn / (tn + fp)
    gmean = np.sqrt(phish_recall * legit_recall)

    print(f"\n{name}:")
    print(f"  Accuracy:        {acc:.4f}")
    print(f"  🎯 Phishing Recall: {phish_recall:.4f} (True Positive Rate)")
    print(f"  Legit Recall:    {legit_recall:.4f}")
    print(f"  G-Mean:          {gmean:.4f}")
    print(f"  AUC:             {roc_auc_score(y_test, y_prob):.4f}")
    print(f"  Missed Phishing: {fn} | False Alarms: {fp}")

    if acc >= 0.9999:
        print("  ⚠️  WARNING: Suspiciously high accuracy - possible data leakage!")
    elif acc >= 0.97:
        print("  ✅ Realistic accuracy achieved")

    return {
        'accuracy': acc,
        'phishing_recall': phish_recall,
        'legit_recall': legit_recall,
        'gmean': gmean,
        'auc': roc_auc_score(y_test, y_prob)
    }

results = {}
for name, model in [
    ('LightGBM', lgb_model),
    ('XGBoost', xgb_model),
    ('CatBoost', cat_model),
    ('Random Forest', rf_model)
]:
    results[name] = evaluate(name, model, X_test_scaled, y_test)

print("\n" + "="*70)

# ============================================================================
# 8. SAVE MODEL BUNDLE
# ============================================================================
print("\n8. Saving model bundle...")

MODEL_DIR = 'models'
os.makedirs(MODEL_DIR, exist_ok=True)

bundle = {
    # Models
    'gradient_boosting': lgb_model,
    'xgboost': xgb_model,
    'catboost': cat_model,
    'random_forest': rf_model,

    # Preprocessing
    'scaler': scaler,
    'feature_names': FEATURE_NAMES,

    # Metrics
    'model_metrics': {
        'gradient_boosting': results['LightGBM'],
        'xgboost': results['XGBoost'],
        'catboost': results['CatBoost'],
        'random_forest': results['Random Forest']
    },

    # Metadata
    'optimal_threshold': 0.5,
    'training_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
    'dataset': 'phishurl.csv (235,795 rows, URLSimilarityIndex REMOVED)',
    'version': '3.0_REALISTIC',
    'data_leakage_fixed': True,
    'models_count': 4
}

BUNDLE_PATH = os.path.join(MODEL_DIR, 'phishing_model_bundle_REALISTIC_v3.pkl')
with open(BUNDLE_PATH, 'wb') as f:
    pickle.dump(bundle, f, protocol=pickle.HIGHEST_PROTOCOL)

size_mb = os.path.getsize(BUNDLE_PATH) / (1024 * 1024)
print(f"   ✅ Saved: {BUNDLE_PATH}")
print(f"   Size: {size_mb:.1f} MB")
print(f"   Models: 4 (LightGBM, XGBoost, CatBoost, Random Forest)")
print(f"   Features: {len(FEATURE_NAMES)}")

# ============================================================================
# 9. SUMMARY
# ============================================================================
print("\n" + "="*70)
print("TRAINING COMPLETE")
print("="*70)
print(f"\nBest Model: LightGBM")
print(f"  Accuracy: {results['LightGBM']['accuracy']:.4f}")
print(f"  🎯 Phishing Recall: {results['LightGBM']['phishing_recall']:.4f}")
print(f"  G-Mean: {results['LightGBM']['gmean']:.4f}")
print(f"\nData Leakage: ✅ FIXED (URLSimilarityIndex removed)")
print(f"Bundle: {BUNDLE_PATH}")
print(f"\nFinished: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print("="*70)
