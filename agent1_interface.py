"""
Agent 1: Log Classification and Triage Agent
Uses LSTM model to classify logs and extract IOCs
"""

import os
import pickle
import numpy as np
import pandas as pd
import re
from typing import Dict, List, Any

import tensorflow as tf
from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing.sequence import pad_sequences


class Agent1:
    def __init__(self,
                 model_path: str = None,
                 tokenizer_path: str = None,
                 label_encoder_path: str = None):

        # -------------------------------------------------
        # Safe paths (works on Windows + Linux)
        # Files are directly inside agent1/
        # -------------------------------------------------
        base_dir = os.path.dirname(__file__)

        self.model_path = model_path or os.path.join(base_dir, "lstm_log_classifier.h5")
        self.tokenizer_path = tokenizer_path or os.path.join(base_dir, "tokenizer.pkl")
        self.label_encoder_path = label_encoder_path or os.path.join(base_dir, "label_encoder.pkl")

        # Load models
        self.load_models()

        # IOC patterns
        self.ioc_patterns = {
            'ip': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            'domain': r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b',
            'md5': r'\b[a-fA-F0-9]{32}\b',
            'sha1': r'\b[a-fA-F0-9]{40}\b',
            'sha256': r'\b[a-fA-F0-9]{64}\b',
            'url': r'https?://[^\s<>"\']+|www\.[^\s<>"\']+',
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b',
            'file_path': r'[A-Za-z]:\\(?:[^\\]+\\)*[^\\]+|/(?:[^/]+/)*[^/]+',
            'cmd': r'(powershell|cmd\.exe|bash|sh|wmic|schtasks|regsvr32|rundll32)',
            'port': r':(\d{1,5})\b'
        }

        print(f"\n✅ Agent 1 initialized")
        print(f"   Model: {self.model_path}")
        print(f"   Tokenizer: {self.tokenizer_path}")
        print(f"   Label Encoder: {self.label_encoder_path}")

    # =====================================================
    # Load models
    # =====================================================
    def load_models(self):
        try:
            self.model = load_model(self.model_path)

            with open(self.tokenizer_path, 'rb') as f:
                self.tokenizer = pickle.load(f)

            with open(self.label_encoder_path, 'rb') as f:
                self.label_encoder = pickle.load(f)

            self.max_len = getattr(self.tokenizer, 'max_len', 100)

            print("   ✔ Models loaded successfully")

        except Exception as e:
            print(f"❌ Error loading models: {e}")
            raise

    # =====================================================
    # Classification
    # =====================================================
    def classify(self, log_text: str) -> Dict[str, Any]:

        sequences = self.tokenizer.texts_to_sequences([log_text])
        padded = pad_sequences(sequences, maxlen=self.max_len, padding='post')

        predictions = self.model.predict(padded, verbose=0)

        class_idx = np.argmax(predictions[0])
        confidence = float(predictions[0][class_idx])

        try:
            label = self.label_encoder.inverse_transform([class_idx])[0]
        except:
            label = f"class_{class_idx}"

        iocs = self.extract_iocs(log_text)
        severity = self.calculate_severity(label, confidence)

        return {
            'label': label,
            'confidence': confidence,
            'severity': severity,
            'iocs': iocs,
            'timestamp': pd.Timestamp.now().isoformat()
        }

    # =====================================================
    # IOC Extraction
    # =====================================================
    def extract_iocs(self, text: str) -> List[Dict]:
        iocs = []

        for ioc_type, pattern in self.ioc_patterns.items():
            matches = re.finditer(pattern, text, re.IGNORECASE)

            for match in matches:
                value = match.group(0).strip()

                if not value:
                    continue

                iocs.append({
                    'type': ioc_type,
                    'value': value
                })

        return iocs

    # =====================================================
    # Severity logic
    # =====================================================
    def calculate_severity(self, label: str, confidence: float) -> str:

        mapping = {
            'malicious': 'critical',
            'malware': 'critical',
            'attack': 'high',
            'suspicious': 'medium',
            'anomaly': 'low',
            'normal': 'info',
            'benign': 'info'
        }

        base = mapping.get(label.lower(), 'medium')

        if confidence > 0.9 and base == 'low':
            return 'medium'

        return base


# =========================================================
# Standalone test
# =========================================================
if __name__ == "__main__":
    agent = Agent1()

    test = "Connection to 192.168.1.100:4444 detected"

    result = agent.classify(test)

    print("\nResult:")
    print(result)
