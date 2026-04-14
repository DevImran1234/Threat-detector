"""
Utility functions for Multi Agentic System

"""

import json
import yaml
import logging
import sys
import os
from typing import Dict, List, Any, Optional
from datetime import datetime
import hashlib

def setup_logging(name: str = "mitre_pipeline", 
                  level: str = "INFO",
                  verbose: bool = False,
                  log_file: str = None) -> logging.Logger:
    """
    Setup logging configuration
    
    Args:
        name: Logger name
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        verbose: If True, also log to console
        log_file: Path to log file
        
    Returns:
        Configured logger
    """
    # Create logs directory if it doesn't exist
    if log_file:
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
    
    # Configure logging
    logger = logging.getLogger(name)
    
    # Remove existing handlers
    logger.handlers.clear()
    
    # Set level
    logger.setLevel(getattr(logging, level.upper()))
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Console handler (if verbose)
    if verbose:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
    
    # File handler (if log_file specified)
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    return logger

def load_config(config_path: str) -> Dict:
    """
    Load configuration from YAML or JSON file
    
    Args:
        config_path: Path to configuration file
        
    Returns:
        Configuration dictionary
    """
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Config file not found: {config_path}")
    
    with open(config_path, 'r') as f:
        if config_path.endswith('.yaml') or config_path.endswith('.yml'):
            return yaml.safe_load(f)
        elif config_path.endswith('.json'):
            return json.load(f)
        else:
            # Try both formats
            try:
                return yaml.safe_load(f)
            except:
                f.seek(0)
                return json.load(f)

def save_config(config: Dict, config_path: str):
    """
    Save configuration to file
    
    Args:
        config: Configuration dictionary
        config_path: Path to save configuration
    """
    os.makedirs(os.path.dirname(config_path), exist_ok=True)
    
    with open(config_path, 'w') as f:
        if config_path.endswith('.yaml') or config_path.endswith('.yml'):
            yaml.dump(config, f, default_flow_style=False)
        elif config_path.endswith('.json'):
            json.dump(config, f, indent=2)
        else:
            # Default to YAML
            yaml.dump(config, f, default_flow_style=False)

def generate_id(text: str, prefix: str = "") -> str:
    """
    Generate a unique ID from text
    
    Args:
        text: Text to hash
        prefix: Prefix for the ID
        
    Returns:
        Unique ID string
    """
    # Create hash
    hash_obj = hashlib.md5(text.encode())
    hash_str = hash_obj.hexdigest()[:8]  # First 8 chars
    
    # Add timestamp for uniqueness
    timestamp = datetime.now().strftime("%H%M%S")
    
    return f"{prefix}{hash_str}-{timestamp}"

def save_result_to_file(result: Dict, filepath: str):
    """
    Save result to JSON file
    
    Args:
        result: Result dictionary
        filepath: Path to save file
    """
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    
    with open(filepath, 'w') as f:
        json.dump(result, f, indent=2, default=str)

def load_results_from_file(filepath: str) -> List[Dict]:
    """
    Load results from JSON file
    
    Args:
        filepath: Path to results file
        
    Returns:
        List of result dictionaries
    """
    if not os.path.exists(filepath):
        return []
    
    with open(filepath, 'r') as f:
        return json.load(f)

def extract_iocs_from_text(text: str) -> Dict[str, List[str]]:
    """
    Extract IOCs from text using regex patterns
    
    Args:
        text: Text to analyze
        
    Returns:
        Dictionary of IOC types and values
    """
    import re
    
    patterns = {
        'ip': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
        'domain': r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b',
        'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        'url': r'https?://[^\s<>"\']+|www\.[^\s<>"\']+',
        'md5': r'\b[a-fA-F0-9]{32}\b',
        'sha1': r'\b[a-fA-F0-9]{40}\b',
        'sha256': r'\b[a-fA-F0-9]{64}\b',
        'windows_path': r'[A-Za-z]:\\(?:[^\\]+\\)*[^\\]+',
        'unix_path': r'/(?:[^/]+/)*[^/]+',
        'port': r':(\d{1,5})\b'
    }
    
    iocs = {}
    for ioc_type, pattern in patterns.items():
        matches = re.findall(pattern, text, re.IGNORECASE)
        if matches:
            iocs[ioc_type] = list(set(matches))  # Remove duplicates
    
    return iocs

def calculate_risk_score(confidence: float, severity: str, 
                        ioc_count: int = 0) -> float:
    """
    Calculate risk score from multiple factors
    
    Args:
        confidence: Confidence score (0-1)
        severity: Severity level (info, low, medium, high, critical)
        ioc_count: Number of IOCs detected
        
    Returns:
        Risk score (0-100)
    """
    severity_weights = {
        'info': 0.1,
        'low': 0.3,
        'medium': 0.6,
        'high': 0.8,
        'critical': 1.0
    }
    
    severity_weight = severity_weights.get(severity.lower(), 0.5)
    
    # Base score from confidence and severity
    base_score = confidence * severity_weight * 100
    
    # Add bonus for IOCs
    ioc_bonus = min(ioc_count * 5, 20)  # Max 20 points for IOCs
    
    risk_score = min(base_score + ioc_bonus, 100)
    
    return round(risk_score, 1)

def format_timestamp(timestamp: datetime = None) -> str:
    """
    Format timestamp for display
    
    Args:
        timestamp: Datetime object (defaults to now)
        
    Returns:
        Formatted timestamp string
    """
    if timestamp is None:
        timestamp = datetime.now()
    
    return timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

def validate_log_entry(log: str) -> bool:
    """
    Validate log entry
    
    Args:
        log: Log entry string
        
    Returns:
        True if valid, False otherwise
    """
    if not log or not isinstance(log, str):
        return False
    
    if len(log.strip()) == 0:
        return False
    
    # Additional validation rules can be added here
    return True

def get_file_size(filepath: str) -> str:
    """
    Get human-readable file size
    
    Args:
        filepath: Path to file
        
    Returns:
        Human-readable size string
    """
    if not os.path.exists(filepath):
        return "0 B"
    
    size_bytes = os.path.getsize(filepath)
    
    # Convert to human-readable format
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0
    
    return f"{size_bytes:.2f} PB"

def create_directory_structure(base_path: str, structure: Dict):
    """
    Create directory structure
    
    Args:
        base_path: Base directory path
        structure: Dictionary representing directory structure
    """
    if not os.path.exists(base_path):
        os.makedirs(base_path)
    
    for name, contents in structure.items():
        path = os.path.join(base_path, name)
        
        if isinstance(contents, dict):
            # It's a directory
            os.makedirs(path, exist_ok=True)
            create_directory_structure(path, contents)
        else:
            # It's a file (contents is file content)
            with open(path, 'w') as f:
                f.write(contents)

# Test utilities
if __name__ == "__main__":
    # Test logging
    logger = setup_logging("test", verbose=True)
    logger.info("Test log message")
    
    # Test ID generation
    test_id = generate_id("test log entry", "LOG-")
    print(f"Generated ID: {test_id}")
    
    # Test IOC extraction
    test_text = "Connection to 192.168.1.100:443 from user@example.com"
    iocs = extract_iocs_from_text(test_text)
    print(f"Extracted IOCs: {iocs}")
    
    # Test risk score calculation
    risk = calculate_risk_score(0.8, "high", 3)
    print(f"Risk score: {risk}")