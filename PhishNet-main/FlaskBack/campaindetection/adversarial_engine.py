import numpy as np
import logging

logger = logging.getLogger(__name__)

class AdversarialEngine:
    """
    Handles generation of adversarial examples and robustness evaluation
    for the phishing ML models.
    """
    
    def __init__(self, models, feature_names):
        self.models = models
        self.feature_names = feature_names

    def generate_perturbations(self, X):
        """
        Generate small, non-obvious perturbations of the input features.
        Used to test if the model is brittle or 'overfitted' to specific markers.
        """
        X_adv = X.copy()
        
        # 1. Perturb numeric features slightly (e.g. ratios)
        numeric_indices = [i for i, name in enumerate(self.feature_names) 
                          if 'ratio' in name.lower() or 'length' in name.lower()]
        
        if numeric_indices:
            # Add small Gaussian noise to numeric features
            noise = np.random.normal(0, 0.05, X_adv[:, numeric_indices].shape)
            X_adv[:, numeric_indices] += noise
            
        # 2. Randomly 'flip' a few boolean/categorical features (if possible)
        # This simulates an attacker changing a single DOM marker
        flip_count = min(3, len(self.feature_names) // 10)
        random_indices = np.random.choice(len(self.feature_names), flip_count, replace=False)
        
        for idx in random_indices:
            # Assuming binary features for the flip test
            if X_adv[0, idx] in [0, 1]:
                X_adv[0, idx] = 1 - X_adv[0, idx]

        return np.clip(X_adv, 0, 1) # Ensure we stay in reasonable feature bounds

    def evaluate_robustness(self, X_original, original_prob, threshold=0.5):
        """
        Simulate 'Certified Robustness' by checking if multiple adversarial 
        perturbations change the prediction class.
        """
        perturbations = 5
        predictions = []
        
        for _ in range(perturbations):
            X_adv = self.generate_perturbations(X_original)
            
            # Use the primary/ensemble consensus for robustness check
            adv_probs = []
            for model in self.models.values():
                try:
                    if hasattr(model, 'predict_proba'):
                        adv_probs.append(model.predict_proba(X_adv)[0, 1])
                except:
                    continue
            
            if adv_probs:
                adv_consensus = np.mean(adv_probs)
                predictions.append(1 if adv_consensus >= threshold else 0)
        
        # Original class
        original_class = 1 if original_prob >= threshold else 0
        
        # Robustness score: % of perturbations that yielded the SAME class
        stability = predictions.count(original_class) / perturbations
        
        return {
            "is_stable": stability >= 0.8,
            "stability_score": stability,
            "adversarial_risk": 1.0 - stability
        }

    def get_learned_embedding(self, X):
        """
        Generates a semantic embedding from the internal layers of the ensemble.
        Used for resilient clustering where HTML hashes might change.
        """
        # We concatenate the probabilities of all models as a basic 'semantic vector'
        # In a real deep learning setup, we'd use a hidden layer. 
        # Here we use the ensemble's prediction space distribution.
        embedding = []
        for name, model in self.models.items():
            try:
                if hasattr(model, 'predict_proba'):
                    prob = model.predict_proba(X)[0, 1]
                    embedding.append(prob)
                else:
                    embedding.append(model.predict(X)[0])
            except:
                embedding.append(0.5)
        
        # Add some key weighted features to the embedding for infrastructure bias
        # e.g., if we had ASN or IP-reputation-class features
        
        return np.array(embedding).tolist()
