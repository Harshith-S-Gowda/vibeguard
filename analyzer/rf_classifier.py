"""
ShipSafe - Experimental Random Forest Classifier
Classifies structured features into Legitimate vs Suspicious to support investigation.
Output: Probability P(Suspicious) and Feature Importances.
"""

import math
import random
from typing import Dict, Any, List, Tuple

FEATURE_NAMES = [
    "name_similarity_score",     # 0: Float 0.0 - 1.0
    "is_lookalike",              # 1: 0 or 1
    "is_known_publisher",        # 2: 0 or 1
    "publisher_mismatch",        # 3: 0 or 1
    "network_calls_count",       # 4: Int count
    "credential_access_count",   # 5: Int count
    "dynamic_execution_count",   # 6: Int count
    "build_scripts_count",       # 7: Int count
    "obfuscation_count",         # 8: Int count
    "hardware_mismatch",         # 9: 0 or 1
    "pin_conflict",              # 10: 0 or 1
    "network_permitted"          # 11: 0 or 1
]

def extract_feature_vector(rule_output: Dict[str, Any], network_permitted: bool = False) -> List[float]:
    dims = rule_output["dimensions"]
    d1 = dims["name_similarity"]
    d2 = dims["publisher_metadata"]
    d3 = dims["static_source"]["indicators"]
    d4 = dims["hardware_context"]

    return [
        float(d1["similarity_score"]),
        1.0 if d1["is_lookalike"] else 0.0,
        1.0 if d2["is_known_publisher"] else 0.0,
        1.0 if d2["publisher_mismatch"] else 0.0,
        float(d3["network_calls"]),
        float(d3["credential_access"]),
        float(d3["dynamic_execution"]),
        float(d3["build_scripts"]),
        float(d3["obfuscation"]),
        1.0 if d4["hardware_mismatch"] else 0.0,
        1.0 if d4["pin_conflict"] else 0.0,
        1.0 if network_permitted else 0.0
    ]

# Synthetic balanced dataset of PlatformIO / Arduino libraries and controlled lookalikes
TRAINING_DATA = [
    # Legitimate libraries (label = 0)
    ([1.0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0], 0),  # ArduinoJson (Clean parser)
    ([1.0, 0, 1, 0, 3, 0, 0, 0, 0, 0, 0, 1], 0),  # PubSubClient (Legit MQTT with net permitted)
    ([1.0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0], 0),  # Adafruit_Sensor
    ([1.0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0], 0),  # DHT-sensor-library
    ([1.0, 0, 1, 0, 4, 0, 0, 0, 0, 0, 0, 1], 0),  # ESPAsyncWebServer
    ([1.0, 0, 1, 0, 2, 0, 0, 0, 0, 0, 0, 1], 0),  # AsyncTCP
    ([1.0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0], 0),  # Wire
    ([1.0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0], 0),  # SPI
    ([0.2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 0),  # Simple custom math lib
    ([0.3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 0),  # FastLED legitimate driver

    # Suspicious lookalikes & malicious fixtures (label = 1)
    ([0.9, 1, 0, 1, 2, 1, 0, 0, 0, 1, 0, 0], 1),  # Arduin0Json (Lookalike + Wifi credential exfil)
    ([0.9, 1, 0, 1, 2, 1, 0, 0, 0, 0, 0, 1], 1),  # PubSubCllient (Lookalike + PSK sniffing)
    ([0.9, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0], 1),  # Adafru1t_Sensor (extra_scripts build hook)
    ([0.4, 0, 0, 0, 2, 0, 0, 0, 0, 1, 0, 0], 1),  # DHT22_Fast (Unrelated name, unexpected network)
    ([0.5, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0], 1),  # OLED_Display (NVS flash credential access)
    ([0.3, 0, 0, 0, 0, 0, 1, 0, 2, 0, 0, 0], 1),  # Blynk_Pro_Fix (XOR obfuscation + dynamic execution)
    ([0.8, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0], 1),  # BMP280_AirPressure (Bootstrap pin GPIO0 tampering)
    ([0.9, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0], 1),  # ESPAsyncWebserver-lite (Trojan server lookalike)
]

class DecisionTreeNode:
    def __init__(self, feature_idx=None, threshold=None, left=None, right=None, value=None):
        self.feature_idx = feature_idx
        self.threshold = threshold
        self.left = left
        self.right = right
        self.value = value

    @property
    def is_leaf(self):
        return self.value is not None

class SimpleRandomForest:
    def __init__(self, n_estimators: int = 15, max_depth: int = 5, min_samples_split: int = 2):
        self.n_estimators = n_estimators
        self.max_depth = max_depth
        self.min_samples_split = min_samples_split
        self.trees: List[DecisionTreeNode] = []
        self.feature_importances: Dict[str, float] = {}

    def fit(self, X: List[List[float]], y: List[int]):
        random.seed(42)
        n_features = len(X[0])
        max_features = int(math.sqrt(n_features)) + 1
        
        self.trees = []
        feature_counts = [0] * n_features

        for _ in range(self.n_estimators):
            # Bootstrap sample
            indices = [random.randint(0, len(X) - 1) for _ in range(len(X))]
            sample_X = [X[i] for i in indices]
            sample_y = [y[i] for i in indices]

            tree = self._build_tree(sample_X, sample_y, depth=0, max_features=max_features, feature_counts=feature_counts)
            self.trees.append(tree)

        # Normalize feature importances
        total_splits = sum(feature_counts) or 1
        self.feature_importances = {
            FEATURE_NAMES[i]: round(feature_counts[i] / total_splits, 3)
            for i in range(n_features)
        }

    def _build_tree(self, X, y, depth, max_features, feature_counts):
        n_samples = len(X)
        n_labels = len(set(y))

        if depth >= self.max_depth or n_labels <= 1 or n_samples < self.min_samples_split:
            leaf_value = sum(y) / n_samples if n_samples > 0 else 0.0
            return DecisionTreeNode(value=leaf_value)

        # Random subset of features
        all_features = list(range(len(X[0])))
        feat_indices = random.sample(all_features, min(max_features, len(all_features)))

        best_feat, best_thresh = self._best_split(X, y, feat_indices)
        if best_feat is None:
            return DecisionTreeNode(value=sum(y) / n_samples)

        feature_counts[best_feat] += 1

        # Split
        left_X, left_y, right_X, right_y = [], [], [], []
        for i in range(len(X)):
            if X[i][best_feat] <= best_thresh:
                left_X.append(X[i])
                left_y.append(y[i])
            else:
                right_X.append(X[i])
                right_y.append(y[i])

        if not left_X or not right_X:
            return DecisionTreeNode(value=sum(y) / n_samples)

        left = self._build_tree(left_X, left_y, depth + 1, max_features, feature_counts)
        right = self._build_tree(right_X, right_y, depth + 1, max_features, feature_counts)
        return DecisionTreeNode(feature_idx=best_feat, threshold=best_thresh, left=left, right=right)

    def _best_split(self, X, y, feat_indices):
        best_gain = -1.0
        best_feat = None
        best_thresh = None
        current_gini = self._gini(y)

        for feat in feat_indices:
            values = sorted(set(row[feat] for row in X))
            for i in range(len(values) - 1):
                thresh = (values[i] + values[i + 1]) / 2.0
                left_y = [y[j] for j in range(len(X)) if X[j][feat] <= thresh]
                right_y = [y[j] for j in range(len(X)) if X[j][feat] > thresh]

                if not left_y or not right_y:
                    continue

                p_left = len(left_y) / len(y)
                p_right = len(right_y) / len(y)
                gain = current_gini - (p_left * self._gini(left_y) + p_right * self._gini(right_y))

                if gain > best_gain:
                    best_gain = gain
                    best_feat = feat
                    best_thresh = thresh

        return best_feat, best_thresh

    def _gini(self, y):
        if not y:
            return 0.0
        p1 = sum(y) / len(y)
        p0 = 1.0 - p1
        return 1.0 - (p0 ** 2 + p1 ** 2)

    def predict_proba(self, X: List[List[float]]) -> List[float]:
        probas = []
        for row in X:
            tree_preds = [self._predict_tree(tree, row) for tree in self.trees]
            probas.append(sum(tree_preds) / len(tree_preds))
        return probas

    def _predict_tree(self, node: DecisionTreeNode, x: List[float]) -> float:
        if node.is_leaf:
            return node.value
        if x[node.feature_idx] <= node.threshold:
            return self._predict_tree(node.left, x)
        return self._predict_tree(node.right, x)

# Global trained model instance
_MODEL = None

def get_trained_model():
    global _MODEL
    if _MODEL is None:
        X = [item[0] for item in TRAINING_DATA]
        y = [item[1] for item in TRAINING_DATA]
        _MODEL = SimpleRandomForest(n_estimators=15, max_depth=4)
        _MODEL.fit(X, y)
    return _MODEL

def run_rf_classification(feature_vector: List[float]) -> Dict[str, Any]:
    model = get_trained_model()
    prob_suspicious = model.predict_proba([feature_vector])[0]
    
    verdict = "SUSPICIOUS" if prob_suspicious >= 0.50 else "LEGITIMATE"
    confidence = prob_suspicious if verdict == "SUSPICIOUS" else (1.0 - prob_suspicious)

    return {
        "verdict": verdict,
        "prob_suspicious": round(prob_suspicious, 3),
        "prob_legitimate": round(1.0 - prob_suspicious, 3),
        "confidence_percentage": round(confidence * 100, 1),
        "feature_importances": model.feature_importances,
        "feature_vector": {FEATURE_NAMES[i]: feature_vector[i] for i in range(len(FEATURE_NAMES))}
    }
