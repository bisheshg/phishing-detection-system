"""
Experiment with various training parameters to understand their impact
Tests multiple learning rates, tree depths, and regularization strengths
"""

import numpy as np
import pandas as pd
import warnings
import os
import pickle
from datetime import datetime

warnings.filterwarnings('ignore')

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import RobustScaler
from sklearn.metrics import (
    accuracy_score, f1_score, recall_score, precision_score,
    confusion_matrix, balanced_accuracy_score, roc_auc_score
)

import lightgbm as lgb
import xgboost as xgb
from catboost import CatBoostClassifier

def gmean_score(y_true, y_pred):
    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel()
    sensitivity = tp / (tp + fn + 1e-9)
    specificity = tn / (tn + fp + 1e-9)
    return np.sqrt(sensitivity * specificity)

def evaluate_model_quick(name, model, X_test, y_test):
    """Quick evaluation without printing"""
    y_prob = model.predict_proba(X_test)[:, 1]
    y_pred = (y_prob >= 0.5).astype(int)

    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()

    return {
        'Model': name,
        'Accuracy': round(accuracy_score(y_test, y_pred), 4),
        'F1': round(f1_score(y_test, y_pred), 4),
        'GMean': round(gmean_score(y_test, y_pred), 4),
        'AUC': round(roc_auc_score(y_test, y_prob), 4),
        'Recall_Phishing': round(tp / (tp + fn + 1e-9), 4),
        'Recall_Legit': round(tn / (tn + fp + 1e-9), 4),
    }

print("="*80)
print("PARAMETER EXPERIMENTATION - PHISHING DETECTION")
print("="*80)

# Load and preprocess data
df = pd.read_csv('PhishNet-main/FlaskBack/phishurl.csv')

# Drop leaky features
DROP_COLS = ['FILENAME', 'URL', 'Domain', 'TLD', 'Title', 'URLSimilarityIndex']
df_clean = df.drop(columns=DROP_COLS).copy()

# Outlier capping
HEAVY_TAILED = ['LineOfCode', 'LargestLineLength', 'NoOfExternalRef',
                'NoOfSelfRef', 'NoOfCSS', 'NoOfJS', 'NoOfImage',
                'NoOfEmptyRef', 'URLLength']
for col in HEAVY_TAILED:
    if col in df_clean.columns:
        df_clean[col] = df_clean[col].clip(upper=df_clean[col].quantile(0.995))

# Feature engineering
df_clean['ObfuscationIPRisk'] = df_clean['IsDomainIP'] * df_clean['HasObfuscation']
df_clean['InsecurePasswordField'] = (1 - df_clean['IsHTTPS']) * df_clean['HasPasswordField']
df_clean['PageCompletenessRatio'] = df_clean['NoOfSelfRef'] / (df_clean['NoOfExternalRef'] + 1)
df_clean['LegitContentScore'] = (df_clean['HasTitle'] + df_clean['HasFavicon'] +
                                  df_clean['HasDescription'] + df_clean['HasCopyrightInfo'] +
                                  df_clean['IsResponsive'])
df_clean['SuspiciousFinancialFlag'] = ((df_clean['Bank'] + df_clean['Pay'] + df_clean['Crypto']) *
                                        (1 - df_clean['HasCopyrightInfo']))
df_clean['TitleMatchCombined'] = np.sqrt(df_clean['DomainTitleMatchScore'] * df_clean['URLTitleMatchScore'])

df_clean.drop(columns=['NoOfLettersInURL', 'URLTitleMatchScore'], inplace=True)

# Log transforms
LOG_COLS = ['LineOfCode', 'LargestLineLength', 'NoOfExternalRef', 'NoOfSelfRef',
            'NoOfCSS', 'NoOfJS', 'NoOfImage', 'NoOfEmptyRef', 'URLLength', 'DomainLength']
for col in LOG_COLS:
    if col in df_clean.columns:
        df_clean[f'{col}_log'] = np.log1p(df_clean[col])

# Split and scale
X = df_clean.drop(columns=['label'])
y = df_clean['label']

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.20, random_state=42, stratify=y
)

scaler = RobustScaler()
X_train_scaled = pd.DataFrame(scaler.fit_transform(X_train), columns=X.columns, index=X_train.index)
X_test_scaled = pd.DataFrame(scaler.transform(X_test), columns=X.columns, index=X_test.index)

X_tr, X_val, y_tr, y_val = train_test_split(
    X_train_scaled, y_train, test_size=0.15, stratify=y_train, random_state=42
)

print(f"Data loaded: {X_train.shape[0]} train, {X_test.shape[0]} test, {X.shape[1]} features")
print(f"URLSimilarityIndex removed to prevent data leakage")
print("\n" + "="*80)

# ===== EXPERIMENT 1: Different LEARNING RATES =====
print("EXPERIMENT 1: Impact of Learning Rate (LightGBM)")
print("="*80)

results_lr = []
learning_rates = [0.001, 0.01, 0.05, 0.1, 0.3]

for lr in learning_rates:
    print(f"  Testing learning_rate={lr}...")
    model = lgb.LGBMClassifier(
        objective='binary',
        n_estimators=500,
        learning_rate=lr,
        num_leaves=31,
        max_depth=5,
        min_child_samples=50,
        class_weight='balanced',
        random_state=42,
        n_jobs=-1,
        verbose=-1
    )
    model.fit(X_tr, y_tr, eval_set=[(X_val, y_val)],
              callbacks=[lgb.early_stopping(50, verbose=False)])

    result = evaluate_model_quick(f"LR={lr}", model, X_test_scaled, y_test)
    result['n_iterations'] = model.best_iteration_
    results_lr.append(result)

df_lr = pd.DataFrame(results_lr)
print("\nResults:")
print(df_lr[['Model', 'Accuracy', 'F1', 'GMean', 'AUC', 'n_iterations']].to_string(index=False))

# ===== EXPERIMENT 2: Different TREE DEPTHS =====
print("\n" + "="*80)
print("EXPERIMENT 2: Impact of Max Depth (XGBoost)")
print("="*80)

results_depth = []
depths = [3, 5, 7, 10, 15]
n_legit = (y_train == 0).sum()
n_phish = (y_train == 1).sum()
spw = n_legit / n_phish

for depth in depths:
    print(f"  Testing max_depth={depth}...")
    model = xgb.XGBClassifier(
        n_estimators=300,
        max_depth=depth,
        learning_rate=0.01,
        subsample=0.7,
        colsample_bytree=0.7,
        scale_pos_weight=spw,
        tree_method="hist",
        random_state=42,
        n_jobs=-1
    )
    model.fit(X_tr, y_tr, verbose=False)

    result = evaluate_model_quick(f"Depth={depth}", model, X_test_scaled, y_test)
    result['n_iterations'] = model.n_estimators
    results_depth.append(result)

df_depth = pd.DataFrame(results_depth)
print("\nResults:")
print(df_depth[['Model', 'Accuracy', 'F1', 'GMean', 'AUC', 'n_iterations']].to_string(index=False))

# ===== EXPERIMENT 3: Different REGULARIZATION =====
print("\n" + "="*80)
print("EXPERIMENT 3: Impact of Regularization (LightGBM)")
print("="*80)

results_reg = []
reg_params = [
    (0.0, 0.0, "No Reg"),
    (0.1, 0.1, "Light"),
    (1.0, 1.0, "Medium"),
    (5.0, 5.0, "Heavy"),
    (10.0, 10.0, "Very Heavy"),
]

for alpha, lambda_, name in reg_params:
    print(f"  Testing reg_alpha={alpha}, reg_lambda={lambda_} ({name})...")
    model = lgb.LGBMClassifier(
        objective='binary',
        n_estimators=500,
        learning_rate=0.01,
        num_leaves=31,
        max_depth=5,
        reg_alpha=alpha,
        reg_lambda=lambda_,
        class_weight='balanced',
        random_state=42,
        n_jobs=-1,
        verbose=-1
    )
    model.fit(X_tr, y_tr, eval_set=[(X_val, y_val)],
              callbacks=[lgb.early_stopping(50, verbose=False)])

    result = evaluate_model_quick(name, model, X_test_scaled, y_test)
    result['reg_alpha'] = alpha
    result['reg_lambda'] = lambda_
    results_reg.append(result)

df_reg = pd.DataFrame(results_reg)
print("\nResults:")
print(df_reg[['Model', 'Accuracy', 'F1', 'GMean', 'AUC', 'reg_alpha', 'reg_lambda']].to_string(index=False))

# ===== EXPERIMENT 4: Different NUMBER OF ESTIMATORS =====
print("\n" + "="*80)
print("EXPERIMENT 4: Impact of Number of Estimators (CatBoost)")
print("="*80)

results_est = []
n_estimators_list = [100, 300, 500, 1000, 2000]

for n_est in n_estimators_list:
    print(f"  Testing iterations={n_est}...")
    model = CatBoostClassifier(
        iterations=n_est,
        learning_rate=0.02,
        depth=4,
        l2_leaf_reg=5,
        auto_class_weights='Balanced',
        random_seed=42,
        verbose=False,
        early_stopping_rounds=50,
        task_type='CPU'
    )
    model.fit(X_tr, y_tr, eval_set=(X_val, y_val), use_best_model=True)

    result = evaluate_model_quick(f"N={n_est}", model, X_test_scaled, y_test)
    result['best_iteration'] = model.best_iteration_
    results_est.append(result)

df_est = pd.DataFrame(results_est)
print("\nResults:")
print(df_est[['Model', 'Accuracy', 'F1', 'GMean', 'AUC', 'best_iteration']].to_string(index=False))

# ===== EXPERIMENT 5: Different SUBSAMPLE RATES =====
print("\n" + "="*80)
print("EXPERIMENT 5: Impact of Subsampling (LightGBM)")
print("="*80)

results_sub = []
subsample_rates = [0.5, 0.6, 0.7, 0.8, 0.9, 1.0]

for rate in subsample_rates:
    print(f"  Testing subsample={rate}...")
    model = lgb.LGBMClassifier(
        objective='binary',
        n_estimators=500,
        learning_rate=0.01,
        num_leaves=31,
        max_depth=5,
        subsample=rate,
        colsample_bytree=rate,  # Also vary feature sampling
        reg_alpha=1.0,
        reg_lambda=1.0,
        class_weight='balanced',
        random_state=42,
        n_jobs=-1,
        verbose=-1
    )
    model.fit(X_tr, y_tr, eval_set=[(X_val, y_val)],
              callbacks=[lgb.early_stopping(50, verbose=False)])

    result = evaluate_model_quick(f"Sub={rate}", model, X_test_scaled, y_test)
    results_sub.append(result)

df_sub = pd.DataFrame(results_sub)
print("\nResults:")
print(df_sub[['Model', 'Accuracy', 'F1', 'GMean', 'AUC']].to_string(index=False))

# ===== SUMMARY =====
print("\n" + "="*80)
print("EXPERIMENT SUMMARY")
print("="*80)

print("\n📊 KEY FINDINGS:")
print("\n1. LEARNING RATE:")
print(f"   - Highest G-Mean: {df_lr.loc[df_lr['GMean'].idxmax(), 'Model']} = {df_lr['GMean'].max():.4f}")
print(f"   - Range: {df_lr['GMean'].min():.4f} - {df_lr['GMean'].max():.4f}")

print("\n2. TREE DEPTH:")
print(f"   - Highest G-Mean: {df_depth.loc[df_depth['GMean'].idxmax(), 'Model']} = {df_depth['GMean'].max():.4f}")
print(f"   - Range: {df_depth['GMean'].min():.4f} - {df_depth['GMean'].max():.4f}")

print("\n3. REGULARIZATION:")
print(f"   - Highest G-Mean: {df_reg.loc[df_reg['GMean'].idxmax(), 'Model']} = {df_reg['GMean'].max():.4f}")
print(f"   - Range: {df_reg['GMean'].min():.4f} - {df_reg['GMean'].max():.4f}")

print("\n4. NUMBER OF ESTIMATORS:")
print(f"   - Highest G-Mean: {df_est.loc[df_est['GMean'].idxmax(), 'Model']} = {df_est['GMean'].max():.4f}")
print(f"   - Best iteration avg: {df_est['best_iteration'].mean():.0f}")

print("\n5. SUBSAMPLING:")
print(f"   - Highest G-Mean: {df_sub.loc[df_sub['GMean'].idxmax(), 'Model']} = {df_sub['GMean'].max():.4f}")
print(f"   - Range: {df_sub['GMean'].min():.4f} - {df_sub['GMean'].max():.4f}")

print("\n" + "="*80)
print("EXPERIMENT COMPLETE!")
print("="*80)

# Save all results
results_summary = {
    'learning_rate': df_lr,
    'tree_depth': df_depth,
    'regularization': df_reg,
    'n_estimators': df_est,
    'subsampling': df_sub
}

with open('PhishNet-main/FlaskBack/models/parameter_experiments.pkl', 'wb') as f:
    pickle.dump(results_summary, f)

print("\n✅ Results saved to: PhishNet-main/FlaskBack/models/parameter_experiments.pkl")
