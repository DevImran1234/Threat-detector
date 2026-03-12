"""
Mock tokenizer and label encoder for testing
"""

class SimpleTokenizer:
    def __init__(self):
        self.word_index = {
            'suspicious': 1, 'process': 2, 'execution': 3, 'detected': 4,
            'malware': 5, 'unauthorized': 6, 'access': 7, 'attempt': 8,
            'failed': 9, 'admin': 10
        }
        self.max_len = 100
    
    def texts_to_sequences(self, texts):
        """Convert text to sequences of integers"""
        if isinstance(texts, str):
            texts = [texts]
        sequences = []
        for text in texts:
            seq = [self.word_index.get(word.lower(), 0) for word in text.split()[:self.max_len]]
            sequences.append(seq)
        return sequences


class SimpleLabelEncoder:
    def __init__(self):
        self.classes_ = {0: 'Normal', 1: 'Suspicious', 2: 'Malicious'}
        self.class_to_idx = {v: k for k, v in self.classes_.items()}
    
    def inverse_transform(self, indices):
        """Convert indices back to class labels"""
        return [self.classes_.get(int(i), 'Unknown') for i in indices]
