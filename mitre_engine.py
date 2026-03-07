"""
MITRE ATT&CK Mapper
Maps log patterns to MITRE techniques and calculates risk scores
"""

import json
import yaml
import re
from typing import Dict, List, Any
import os

class MITREMapper:
    def __init__(self, config: Dict = None):
        self.config = config or {}
        
        # Load MITRE knowledge base
        self.knowledge_base = self.load_knowledge_base()
        
        # Load mapping rules
        self.mapping_rules = self.load_mapping_rules()
        
        # Technique weights from config
        self.technique_weights = self.config.get('technique_weights', {
            'T1059': 0.9,   # Command execution
            'T1068': 0.95,  # Exploitation
            'T1071': 0.7,   # C2
            'T1027': 0.6,   # Obfuscation
            'T1036': 0.5,   # Masquerading
            'T1055': 0.85,  # Process injection
            'T1547': 0.8,   # Boot/Logon autostart
            'T1566': 0.75,  # Phishing
            'T1588': 0.65,  # Obtain capabilities
        })
        
        print("✅ MITRE Mapper initialized")
    
    def load_knowledge_base(self) -> Dict:
        """Load MITRE ATT&CK knowledge base"""
        kb_path = self.config.get('knowledge_base', 'mitre_knowledge.json')
        
        if os.path.exists(kb_path):
            try:
                with open(kb_path, 'r') as f:
                    return json.load(f)
            except Exception as e:
                print(f"⚠️ Error loading MITRE knowledge base: {e}")
        
        # Return default knowledge base if file not found
        return self.get_default_knowledge_base()
    
    def load_mapping_rules(self) -> Dict:
        """Load mapping rules from YAML file"""
        rules_path = self.config.get('mapping_rules', 'mapping_rules.yaml')
        
        if os.path.exists(rules_path):
            try:
                with open(rules_path, 'r') as f:
                    return yaml.safe_load(f)
            except Exception as e:
                print(f"⚠️ Error loading mapping rules: {e}")
        
        # Return default rules if file not found
        return self.get_default_mapping_rules()
    
    def map(self, log_text: str, classification: str, 
            confidence: float, iocs: List[Dict] = None) -> Dict:
        """
        Map log to MITRE ATT&CK techniques
        
        Args:
            log_text: Original log text
            classification: Classification from Agent 1
            confidence: Confidence score from Agent 1
            iocs: Extracted IOCs from Agent 1
            
        Returns:
            Dictionary with MITRE mapping results
        """
        iocs = iocs or []
        
        print(f"  Analyzing log for MITRE patterns...")
        
        # Step 1: Rule-based mapping
        rule_based_techniques = self.rule_based_mapping(log_text, classification)
        
        # Step 2: IOC-based mapping
        ioc_based_techniques = self.ioc_based_mapping(iocs)
        
        # Step 3: Combine results
        all_techniques = rule_based_techniques + ioc_based_techniques
        
        # Step 4: Remove duplicates (keep highest confidence)
        unique_techniques = self.deduplicate_techniques(all_techniques)
        
        # Step 5: Calculate risk score
        risk_score = self.calculate_risk_score(unique_techniques, confidence)
        
        # Step 6: Determine primary tactic
        primary_tactic = self.get_primary_tactic(unique_techniques)
        
        return {
            'mitre_techniques': unique_techniques,
            'risk_score': risk_score,
            'primary_tactic': primary_tactic,
            'technique_count': len(unique_techniques),
            'mapping_methods': {
                'rule_based': len(rule_based_techniques),
                'ioc_based': len(ioc_based_techniques)
            }
        }
    
    def rule_based_mapping(self, log_text: str, classification: str) -> List[Dict]:
        """Map using pattern matching rules"""
        techniques = []
        log_lower = log_text.lower()
        
        for rule_name, rule_data in self.mapping_rules.get('rules', {}).items():
            patterns = rule_data.get('patterns', [])
            technique_ids = rule_data.get('mitre_techniques', [])
            base_confidence = rule_data.get('confidence', 0.5)
            
            # Check if any pattern matches
            for pattern in patterns:
                if re.search(pattern, log_lower, re.IGNORECASE):
                    for tech_id in technique_ids:
                        # Get technique details from knowledge base
                        tech_details = self.get_technique_details(tech_id)
                        
                        # Calculate confidence
                        confidence = min(base_confidence + 0.2, 0.95)  # Cap at 0.95
                        
                        techniques.append({
                            'technique_id': tech_id,
                            'name': tech_details.get('name', 'Unknown'),
                            'tactic': tech_details.get('tactic', 'Unknown'),
                            'confidence': confidence,
                            'matched_pattern': pattern,
                            'source': 'rule_based',
                            'description': tech_details.get('description', '')
                        })
                    break  # Found a match, no need to check other patterns
        
        # Classification-based mapping
        classification_techniques = self.mapping_rules.get('classification_mapping', {})
        if classification in classification_techniques:
            for tech_id in classification_techniques[classification]:
                tech_details = self.get_technique_details(tech_id)
                
                techniques.append({
                    'technique_id': tech_id,
                    'name': tech_details.get('name', 'Unknown'),
                    'tactic': tech_details.get('tactic', 'Unknown'),
                    'confidence': 0.6,  # Medium confidence for classification match
                    'source': 'classification',
                    'description': f"Mapped from classification: {classification}"
                })
        
        return techniques
    
    def ioc_based_mapping(self, iocs: List[Dict]) -> List[Dict]:
        """Map IOCs to MITRE techniques"""
        techniques = []
        
        if not iocs:
            return techniques
        
        ioc_mapping = self.mapping_rules.get('ioc_mapping', {})
        
        for ioc in iocs:
            ioc_type = ioc.get('type', '')
            ioc_value = ioc.get('value', '')
            
            # Check if this IOC type maps to any techniques
            if ioc_type in ioc_mapping:
                for tech_id in ioc_mapping[ioc_type]:
                    tech_details = self.get_technique_details(tech_id)
                    
                    techniques.append({
                        'technique_id': tech_id,
                        'name': tech_details.get('name', 'Unknown'),
                        'tactic': tech_details.get('tactic', 'Unknown'),
                        'confidence': 0.7,  # High confidence for IOC match
                        'source': 'ioc_based',
                        'matched_ioc': f"{ioc_type}: {ioc_value[:50]}",
                        'description': f"Mapped from {ioc_type} IOC"
                    })
        
        return techniques
    
    def get_technique_details(self, technique_id: str) -> Dict:
        """Get details for a MITRE technique"""
        # Check knowledge base
        if technique_id in self.knowledge_base.get('techniques', {}):
            return self.knowledge_base['techniques'][technique_id]
        
        # Check sub-techniques
        base_id = technique_id.split('.')[0]
        if base_id in self.knowledge_base.get('techniques', {}):
            base_tech = self.knowledge_base['techniques'][base_id]
            return {
                'name': f"{base_tech.get('name', 'Unknown')} (Sub-technique)",
                'tactic': base_tech.get('tactic', 'Unknown'),
                'description': base_tech.get('description', '')
            }
        
        # Return default if not found
        return {
            'name': 'Unknown Technique',
            'tactic': 'Unknown',
            'description': 'Technique details not available'
        }
    
    def deduplicate_techniques(self, techniques: List[Dict]) -> List[Dict]:
        """Remove duplicate techniques, keeping highest confidence"""
        unique_techs = {}
        
        for tech in techniques:
            tech_id = tech['technique_id']
            
            if tech_id not in unique_techs:
                unique_techs[tech_id] = tech
            elif tech['confidence'] > unique_techs[tech_id]['confidence']:
                unique_techs[tech_id] = tech
        
        return list(unique_techs.values())
    
    def calculate_risk_score(self, techniques: List[Dict], base_confidence: float) -> float:
        """Calculate overall risk score (0-100)"""
        if not techniques:
            return 0
        
        total_weighted_score = 0
        total_weight = 0
        
        for tech in techniques:
            tech_id = tech['technique_id']
            base_id = tech_id.split('.')[0]
            
            # Get weight for this technique
            weight = self.technique_weights.get(base_id, 0.5)
            
            # Calculate score for this technique
            tech_score = tech['confidence'] * weight * 100
            
            total_weighted_score += tech_score
            total_weight += weight
        
        # Average score
        if total_weight > 0:
            avg_score = total_weighted_score / total_weight
        else:
            avg_score = 0
        
        # Adjust based on base confidence
        adjusted_score = avg_score * (0.3 + 0.7 * base_confidence)
        
        # Cap at 100
        return min(adjusted_score, 100)
    
    def get_primary_tactic(self, techniques: List[Dict]) -> str:
        """Determine primary MITRE tactic"""
        if not techniques:
            return "None"
        
        # Count tactics
        tactic_count = {}
        for tech in techniques:
            tactic = tech.get('tactic', 'Unknown')
            tactic_count[tactic] = tactic_count.get(tactic, 0) + 1
        
        # Find most common tactic
        if tactic_count:
            primary = max(tactic_count.items(), key=lambda x: x[1])
            return primary[0]
        
        return "Unknown"
    
    def get_default_knowledge_base(self) -> Dict:
        """Return default MITRE knowledge base"""
        return {
            "version": "1.0",
            "techniques": {
                "T1059": {
                    "name": "Command and Scripting Interpreter",
                    "tactic": "Execution",
                    "description": "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries."
                },
                "T1059.001": {
                    "name": "PowerShell",
                    "tactic": "Execution",
                    "description": "Adversaries may abuse PowerShell to execute malicious commands and scripts."
                },
                "T1059.003": {
                    "name": "Windows Command Shell",
                    "tactic": "Execution",
                    "description": "Adversaries may abuse the Windows command shell for execution."
                },
                "T1071": {
                    "name": "Application Layer Protocol",
                    "tactic": "Command and Control",
                    "description": "Adversaries may use application layer protocols for communication."
                },
                "T1068": {
                    "name": "Exploitation for Privilege Escalation",
                    "tactic": "Privilege Escalation",
                    "description": "Adversaries may exploit vulnerabilities to elevate privileges."
                },
                "T1027": {
                    "name": "Obfuscated Files or Information",
                    "tactic": "Defense Evasion",
                    "description": "Adversaries may obfuscate files or information to avoid detection."
                },
                "T1547": {
                    "name": "Boot or Logon Autostart Execution",
                    "tactic": "Persistence",
                    "description": "Adversaries may configure system settings to automatically execute code at boot or logon."
                }
            }
        }
    
    def get_default_mapping_rules(self) -> Dict:
        """Return default mapping rules"""
        return {
            "rules": {
                "powershell_execution": {
                    "patterns": [
                        r"powershell",
                        r"invoke-expression",
                        r"iex\s",
                        r"-enc\s"
                    ],
                    "mitre_techniques": ["T1059.001", "T1059"],
                    "confidence": 0.8
                },
                "cmd_execution": {
                    "patterns": [
                        r"cmd\.exe",
                        r"command.*line",
                        r"cmd\s+/c"
                    ],
                    "mitre_techniques": ["T1059.003", "T1059"],
                    "confidence": 0.7
                },
                "scheduled_task": {
                    "patterns": [
                        r"schtasks",
                        r"scheduled.*task",
                        r"task.*scheduler"
                    ],
                    "mitre_techniques": ["T1053.005", "T1547"],
                    "confidence": 0.6
                },
                "registry_persistence": {
                    "patterns": [
                        r"reg.*run",
                        r"hklm.*run",
                        r"hkcu.*run",
                        r"registry.*run"
                    ],
                    "mitre_techniques": ["T1547.001"],
                    "confidence": 0.75
                }
            },
            "classification_mapping": {
                "malicious": ["T1204", "T1059"],
                "malware": ["T1204", "T1027"],
                "attack": ["T1190", "T1068"],
                "suspicious": ["T1059", "T1071"]
            },
            "ioc_mapping": {
                "ip": ["T1071", "T1095"],
                "domain": ["T1071", "T1568"],
                "md5": ["T1027", "T1140"],
                "sha256": ["T1027", "T1140"],
                "url": ["T1105", "T1566"]
            }
        }

# Test the mapper
if __name__ == "__main__":
    mapper = MITREMapper()
    
    test_logs = [
        "User executed powershell -enc SQBFAFgAIAAkAGkAbgBwAHUAdAA=",
        "Scheduled task created via schtasks /create",
        "Registry modified at HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "Connection to 192.168.1.100:4444"
    ]
    
    for log in test_logs:
        result = mapper.map(log, "suspicious", 0.8)
        print(f"\nLog: {log[:80]}...")
        print(f"  Techniques: {len(result['mitre_techniques'])}")
        for tech in result['mitre_techniques']:
            print(f"    • {tech['technique_id']}: {tech['name']} ({tech['confidence']:.2f})")
        print(f"  Risk Score: {result['risk_score']:.1f}")
        print(f"  Primary Tactic: {result['primary_tactic']}")