"""
Phishing Detection Training - Data Leakage Fixed
Drops URLSimilarityIndex and uses different training parameters for more realistic results
"""

import numpy as np
import pandas as pd
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

# Boosting
import lightgbm as lgb
import xgboost as xgb
from catboost import CatBoostClassifier

# Custom G-Mean metric
def gmean_score(y_true, y_pred):
    """Geometric mean of per-class recalls."""
    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel()
    sensitivity = tp / (tp + fn + 1e-9)   # Recall for phishing (class 1)
    specificity = tn / (tn + fp + 1e-9)   # Recall for legitimate (class 0)
    return np.sqrt(sensitivity * specificity)

def evaluate_model(name, model, X_test, y_test, threshold=0.5):
    """Evaluate a model with all relevant metrics."""
    if hasattr(model, 'predict_proba'):
        y_prob = model.predict_proba(X_test)[:, 1]
    else:
        y_prob = model.predict(X_test).astype(float)
    y_pred = (y_prob >= threshold).astype(int)

    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()
    rec_phish = tp / (tp + fn + 1e-9)
    rec_legit = tn / (tn + fp + 1e-9)

    result = {
        'Model': name,
        'Threshold': round(threshold, 2),
        'Accuracy': round(accuracy_score(y_test, y_pred), 4),
        'F1': round(f1_score(y_test, y_pred), 4),
        'Precision': round(precision_score(y_test, y_pred), 4),
        'Recall': round(recall_score(y_test, y_pred), 4),
        'BalancedAcc': round(balanced_accuracy_score(y_test, y_pred), 4),
        'GMean': round(gmean_score(y_test, y_pred), 4),
        'AUC': round(roc_auc_score(y_test, y_prob), 4),
        'Recall_Phishing': round(rec_phish, 4),
        'Recall_Legit': round(rec_legit, 4),
    }
    print(f"\n{name} (threshold={threshold:.2f})")
    print(f"  Accuracy={result['Accuracy']:.4f}  F1={result['F1']:.4f}  AUC={result['AUC']:.4f}")
    print(f"  Balanced Acc={result['BalancedAcc']:.4f}  G-Mean={result['GMean']:.4f}")
    print(f"  Recall(Phishing)={result['Recall_Phishing']:.4f}  Recall(Legit)={result['Recall_Legit']:.4f}")
    return result

print("="*80)
print("PHISHING DETECTION TRAINING - LEAKAGE FIXED VERSION")
print("="*80)

# Load data
df = pd.read_csv('PhishNet-main/FlaskBack/phishurl.csv')
print(f"\nDataset shape: {df.shape}")
print(f"Class distribution:\n{df['label'].value_counts()}")

# Drop string columns AND URLSimilarityIndex (the leaky feature!)
DROP_COLS = ['FILENAME', 'URL', 'Domain', 'TLD', 'Title', 'URLSimilarityIndex']
df_clean = df.drop(columns=DROP_COLS).copy()

print(f"\nFeatures after dropping {len(DROP_COLS)} columns: {df_clean.shape[1] - 1}")
print(f"IMPORTANT: URLSimilarityIndex has been REMOVED (was causing data leakage)")

# Outlier capping
HEAVY_TAILED = [
    'LineOfCode', 'LargestLineLength', 'NoOfExternalRef',
    'NoOfSelfRef', 'NoOfCSS', 'NoOfJS', 'NoOfImage',
    'NoOfEmptyRef', 'URLLength'
]
CAP_PCT = 99.5

print(f"\nCapping outliers at {CAP_PCT}th percentile...")
for col in HEAVY_TAILED:
    if col in df_clean.columns:
        cap_val = df_clean[col].quantile(CAP_PCT / 100)
        df_clean[col] = df_clean[col].clip(upper=cap_val)

# Feature Engineering - Interactions
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
REDUNDANT = ['NoOfLettersInURL', 'URLTitleMatchScore']
df_clean.drop(columns=REDUNDANT, inplace=True)

# Log transforms
LOG_COLS = [
    'LineOfCode', 'LargestLineLength', 'NoOfExternalRef',
    'NoOfSelfRef', 'NoOfCSS', 'NoOfJS', 'NoOfImage',
    'NoOfEmptyRef', 'URLLength', 'DomainLength'
]

for col in LOG_COLS:
    if col in df_clean.columns:
        df_clean[f'{col}_log'] = np.log1p(df_clean[col])

feature_cols = [c for c in df_clean.columns if c != 'label']
print(f"Total features after engineering: {len(feature_cols)}")

# Train/Test Split
X = df_clean.drop(columns=['label'])
y = df_clean['label']
FEATURE_NAMES = list(X.columns)

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.20, random_state=42, stratify=y
)

print(f"\nTrain/Test split:")
print(f"  Training: {X_train.shape}")
print(f"  Test: {X_test.shape}")

# Scaling
scaler = RobustScaler()
X_train_scaled = pd.DataFrame(
    scaler.fit_transform(X_train),
    columns=FEATURE_NAMES,
    index=X_train.index
)
X_test_scaled = pd.DataFrame(
    scaler.transform(X_test),
    columns=FEATURE_NAMES,
    index=X_test.index
)

# Validation split for early stopping
X_tr, X_val, y_tr, y_val = train_test_split(
    X_train_scaled, y_train,
    test_size=0.15,
    stratify=y_train,
    random_state=42
)

print(f"\nValidation split created: {X_val.shape}")
print("="*80)
print("TRAINING MODELS WITH DIFFERENT PARAMETERS")
print("="*80)

# ===== EXPERIMENT 1: LightGBM with LOWER learning rate, MORE regularization =====
print("\n1. LightGBM - Lower learning rate (0.01) + More regularization")
lgb_model = lgb.LGBMClassifier(
    objective='binary',
    n_estimators=500,            # Reduced from 1000
    learning_rate=0.01,           # REDUCED from 0.05
    num_leaves=31,                # REDUCED from 63
    max_depth=5,                  # LIMITED depth
    min_child_samples=50,         # INCREASED from 30
    subsample=0.7,                # REDUCED from 0.8
    colsample_bytree=0.7,         # REDUCED from 0.8
    reg_alpha=1.0,                # INCREASED regularization
    reg_lambda=1.0,               # INCREASED regularization
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
print(f"Stopped at iteration: {lgb_model.best_iteration_}")
lgb_result = evaluate_model('LightGBM (conservative)', lgb_model, X_test_scaled, y_test)

# ===== EXPERIMENT 2: XGBoost with DIFFERENT parameters =====
print("\n2. XGBoost - Shallower trees, more regularization")
n_legit = (y_train == 0).sum()
n_phish = (y_train == 1).sum()
spw = n_legit / n_phish

xgb_model = xgb.XGBClassifier(
    n_estimators=300,             # Reduced
    max_depth=4,                  # SHALLOWER trees (from 6)
    learning_rate=0.01,           # LOWER (from 0.05)
    subsample=0.7,
    colsample_bytree=0.7,
    min_child_weight=5,           # INCREASED (from 3)
    gamma=0.3,                    # INCREASED (from 0.1)
    reg_alpha=1.0,                # More regularization
    reg_lambda=2.0,               # More regularization
    scale_pos_weight=spw,
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
print(f"Stopped at iteration: {xgb_model.best_iteration}")
xgb_result = evaluate_model("XGBoost (conservative)", xgb_model, X_test_scaled, y_test)

# ===== EXPERIMENT 3: CatBoost with DIFFERENT depth =====
print("\n3. CatBoost - Shallower trees, slower learning")
cat_model = CatBoostClassifier(
    iterations=500,
    learning_rate=0.02,           # LOWER (from 0.05)
    depth=4,                      # SHALLOWER (from 6)
    l2_leaf_reg=5,                # MORE regularization (from 3)
    border_count=128,
    auto_class_weights='Balanced',
    eval_metric='AUC',
    random_seed=42,
    verbose=False,
    early_stopping_rounds=50,
    task_type='CPU'
)

cat_model.fit(
    X_tr, y_tr,
    eval_set=(X_val, y_val),
    use_best_model=True
)
cat_result = evaluate_model('CatBoost (conservative)', cat_model, X_test_scaled, y_test)

# ===== EXPERIMENT 4: Random Forest with DIFFERENT parameters =====
print("\n4. RandomForest - More trees, limited depth")
rf_model = RandomForestClassifier(
    n_estimators=500,             # MORE trees (from 300)
    max_depth=15,                 # LIMITED depth (was None)
    min_samples_split=20,         # INCREASED (from 10)
    min_samples_leaf=10,          # INCREASED (from 5)
    max_features='sqrt',
    class_weight='balanced_subsample',
    oob_score=True,
    n_jobs=-1,
    random_state=42
)

rf_model.fit(X_train_scaled, y_train)
print(f"OOB Score: {rf_model.oob_score_:.4f}")
rf_result = evaluate_model('RandomForest (conservative)', rf_model, X_test_scaled, y_test)

# ===== SUMMARY =====
print("\n" + "="*80)
print("RESULTS SUMMARY - ALL MODELS")
print("="*80)

results_df = pd.DataFrame([lgb_result, xgb_result, cat_result, rf_result])
results_df = results_df.sort_values('GMean', ascending=False)
print(results_df[['Model', 'Accuracy', 'F1', 'BalancedAcc', 'GMean',
                   'Recall_Phishing', 'Recall_Legit', 'AUC']].to_string(index=False))

# ===== SAVE BEST MODEL =====
print("\n" + "="*80)
print("SAVING BEST MODEL BUNDLE")
print("="*80)

best_model = lgb_model  # Or choose the best based on results_df
best_result = lgb_result

MODEL_DIR = 'PhishNet-main/FlaskBack/models'
os.makedirs(MODEL_DIR, exist_ok=True)

model_metrics = {
    'gradient_boosting': {
        'f1_score': float(best_result['F1']),
        'accuracy': float(best_result['Accuracy']),
        'recall': float(best_result['Recall']),
        'precision': float(best_result['Precision']),
        'balanced_accuracy': float(best_result['BalancedAcc']),
        'gmean': float(best_result['GMean']),
        'auc': float(best_result['AUC']),
    },
    'catboost': {
        'f1_score': float(cat_result['F1']),
        'accuracy': float(cat_result['Accuracy']),
    },
    'random_forest': {
        'f1_score': float(rf_result['F1']),
        'accuracy': float(rf_result['Accuracy']),
    },
}

bundle = {
    'gradient_boosting': lgb_model,
    'catboost': cat_model,
    'random_forest': rf_model,
    'scaler': scaler,
    'feature_names': FEATURE_NAMES,
    'model_metrics': model_metrics,
    'optimal_threshold': 0.5,
    'training_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
    'dataset': 'phishurl.csv (235795 rows) - URLSimilarityIndex REMOVED',
    'best_model': best_result['Model'],
    'version': '2.1-no-leakage',
}

BUNDLE_PATH = os.path.join(MODEL_DIR, 'phishing_model_bundle_no_leakage.pkl')
with open(BUNDLE_PATH, 'wb') as f:
    pickle.dump(bundle, f, protocol=pickle.HIGHEST_PROTOCOL)

size_mb = os.path.getsize(BUNDLE_PATH) / (1024 * 1024)
print(f"✅ Bundle saved: {BUNDLE_PATH} ({size_mb:.1f} MB)")
print(f"✅ Best model: {best_result['Model']}")
print(f"✅ G-Mean: {best_result['GMean']:.4f}")
print(f"✅ Accuracy: {best_result['Accuracy']:.4f}")
print("\n" + "="*80)
print("TRAINING COMPLETE!")
print("="*80)
