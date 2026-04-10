"""
Agent models for multi-agentic cybersecurity system
"""

from typing import List, Dict, Optional
import logging
import re
import hashlib

logger = logging.getLogger(__name__)

class ExternalThreatIntelligenceAgent:
    """
    Agent for cross-referencing threats against external threat intelligence databases.
    Queries VirusTotal, AlienVault OTX, MITRE ATT&CK, AbuseIPDB, and URLhaus.
    """
    def __init__(self):
        self.sources = [
            "VirusTotal",
            "AlienVault OTX",
            "MITRE ATT&CK",
            "AbuseIPDB",
            "URLhaus"
        ]
        self.known_threats = {
            "malware": ["Emotet", "TrickBot", "Mirai", "Conficker"],
            "ransomware": ["REvil", "LockBit", "Conti", "DarkSide"],
            "phishing": ["phishing_campaign_2024", "credential_harvesting"],
            "apt": ["APT-28", "APT-29", "APT-41", "Lazarus"],
            "exploit": ["CVE-2021-44228", "CVE-2021-3156", "CVE-2022-26143"]
        }

    def query_external_sources(self, threat: str) -> Dict[str, Dict]:
        """
        Query all external sources for the given threat.
        Checks threat existence and retrieves history, IOCs, actors, severity, and mitigation.
        """
        findings = {}
        threat_lower = threat.lower()
        
        # Query VirusTotal
        findings["VirusTotal"] = self._query_virustotal(threat)
        
        # Query AlienVault OTX
        findings["AlienVault OTX"] = self._query_alienvault(threat)
        
        # Query MITRE ATT&CK
        findings["MITRE ATT&CK"] = self._query_mitre(threat)
        
        # Query AbuseIPDB
        findings["AbuseIPDB"] = self._query_abusipdb(threat)
        
        # Query URLhaus
        findings["URLhaus"] = self._query_urlhaus(threat)
        
        return findings

    def _query_virustotal(self, threat: str) -> Dict:
        """Query VirusTotal for file/URL/IP/domain reputation"""
        threat_lower = threat.lower()
        
        # Extract potential IOCs from threat
        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', threat)
        domains = re.findall(r'\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b', threat)
        file_hashes = re.findall(r'\b[a-fA-F0-9]{32,64}\b', threat)
        
        detection_ratio = 0
        if ips or domains or file_hashes:
            detection_ratio = 5  # Mock: 5 out of 70 antivirus engines detected
        
        return {
            "found": bool(ips or domains or file_hashes),
            "detection_ratio": f"{detection_ratio}/70",
            "reputation": "malicious" if detection_ratio > 0 else "clean",
            "iocs": {
                "ips": ips,
                "domains": domains,
                "hashes": file_hashes
            },
            "last_analysis_date": "2024-01-15T10:30:00Z"
        }

    def _query_alienvault(self, threat: str) -> Dict:
        """Query AlienVault OTX for pulses and IOCs"""
        threat_lower = threat.lower()
        
        pulses = []
        iocs = []
        
        # Check for known threat patterns
        for category, threats in self.known_threats.items():
            if any(t.lower() in threat_lower for t in threats):
                pulses.append({
                    "name": f"{category.upper()} Campaign",
                    "description": f"Active {category} threat detected",
                    "ioc_count": 20
                })
                iocs.extend([f"ioc_{i}_{hashlib.md5(threat.encode()).hexdigest()[:4]}" for i in range(5)])
        
        return {
            "pulses_found": len(pulses),
            "pulses": pulses,
            "iocs": iocs,
            "community_coverage": len(pulses) > 0
        }

    def _query_mitre(self, threat: str) -> Dict:
        """Query MITRE ATT&CK framework for techniques and tactics"""
        threat_lower = threat.lower()
        
        technique_map = {
            "execution": ["T1059", "T1203", "T1559"],
            "persistence": ["T1547", "T1037", "T1547"],
            "privilege escalation": ["T1548", "T1134", "T1547"],
            "defense evasion": ["T1548", "T1134", "T1140"],
            "credential access": ["T1110", "T1555", "T1187"],
            "lateral movement": ["T1021", "T1570"],
            "collection": ["T1557", "T1185", "T1113"],
            "exfiltration": ["T1020", "T1030", "T1048"],
            "command and control": ["T1071", "T1092", "T1001"]
        }
        
        matched_tactics = []
        matched_techniques = []
        
        for tactic, techniques in technique_map.items():
            if any(word in threat_lower for word in tactic.split()):
                matched_tactics.append(tactic)
                matched_techniques.extend(techniques[:2])
        
        return {
            "tactics": matched_tactics if matched_tactics else ["Reconnaissance"],
            "techniques": list(set(matched_techniques))[:5] if matched_techniques else ["T1592"],
            "framework_coverage": len(matched_techniques) > 0
        }

    def _query_abusipdb(self, threat: str) -> Dict:
        """Query AbuseIPDB for IP reputation"""
        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', threat)
        
        results = []
        for ip in ips:
            results.append({
                "ip": ip,
                "abuse_score": 75,  # Mock score
                "total_reports": 42,
                "is_whitelisted": False
            })
        
        return {
            "ips_checked": len(ips),
            "results": results,
            "found": len(ips) > 0
        }

    def _query_urlhaus(self, threat: str) -> Dict:
        """Query URLhaus for malicious URLs"""
        domains = re.findall(r'https?://\S+|(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}', threat)
        
        malicious_urls = []
        for domain in domains:
            malicious_urls.append({
                "url": domain,
                "threat": "malware_distribution",
                "date_added": "2024-01-14T00:00:00Z"
            })
        
        return {
            "urls_found": len(malicious_urls),
            "malicious_urls": malicious_urls,
            "threat_types": ["malware_distribution", "phishing"]
        }

    def format_output(self, findings: Dict[str, Dict]) -> Dict:
        """
        Format the findings into a structured, professional, and comprehensive report.
        """
        summary = {
            "total_sources_queried": len(findings),
            "sources_with_findings": sum(1 for f in findings.values() if f.get("found") or f.get("pulses_found") or f.get("urls_found")),
            "threat_level": "HIGH" if sum(1 for f in findings.values() if f.get("found")) > 2 else "MEDIUM" if sum(1 for f in findings.values() if f.get("found")) > 0 else "LOW",
            "findings": findings
        }
        return summary

    def handle_limited_info(self, findings: Dict[str, Dict]) -> Dict:
        """
        Handle cases where limited or no information is found.
        """
        return {
            "status": "limited_data",
            "message": "Limited external threat intelligence found. Recommend manual investigation and monitoring.",
            "findings": findings,
            "next_steps": [
                "Enable enhanced monitoring",
                "Check internal security logs",
                "Request additional threat intel sources",
                "Escalate to SOC for investigation"
            ]
        }


class AnomalyDetectionAgent:
    """
    Agent for detecting new, unknown, or novel threats and classifying anomalies.
    Identifies deviations from normal patterns and zero-day threats.
    """
    def __init__(self):
        self.known_categories = [
            "Malware", "Ransomware", "Phishing", "DDoS", "Zero-day exploit", "APT"
        ]
        self.baseline_patterns = {
            "normal_process": ["svchost.exe", "explorer.exe", "winlogon.exe"],
            "normal_ports": [80, 443, 22, 53, 3306],
            "normal_protocols": ["HTTP", "HTTPS", "DNS", "SSH"],
        }

    def detect_anomaly(self, threat_input: str, previous_agent_outputs: Optional[Dict] = None) -> Dict:
        """
        Analyze the input for anomalies and classify the threat.
        Compares against known patterns to detect novel threats.
        """
        threat_lower = threat_input.lower()
        
        # Calculate anomaly score based on suspicious keywords
        anomaly_keywords = {
            "zero_day": 0.9,
            "unknown": 0.8,
            "unusual": 0.7,
            "exploit": 0.8,
            "bypass": 0.7,
            "suspicious": 0.6,
            "unauthorized": 0.7,
            "malware": 0.8,
            "ransomware": 0.85,
            "backdoor": 0.9,
            "c2": 0.85,
            "botnet": 0.85
        }
        
        anomaly_score = 0.3  # Default baseline
        matched_keywords = []
        
        for keyword, score in anomaly_keywords.items():
            if keyword.replace("_", " ") in threat_lower or keyword in threat_lower:
                anomaly_score = max(anomaly_score, score)
                matched_keywords.append(keyword)
        
        # Classify threat based on anomaly analysis
        classification, is_novel, confidence = self._classify_threat(threat_input, anomaly_score)
        
        # Extract behavioral features
        features = self._extract_features(threat_input)
        
        # Calculate similarity to known threats
        similarity_reasoning = self._generate_reasoning(classification, is_novel, confidence, matched_keywords)
        
        return {
            "classification": classification,
            "similarity_reasoning": similarity_reasoning,
            "confidence": confidence,
            "features": features,
            "novel": is_novel,
            "anomaly_score": anomaly_score,
            "matched_indicators": matched_keywords,
            "recommendation": "ESCALATE" if is_novel else "INVESTIGATE" if anomaly_score > 0.6 else "MONITOR"
        }

    def _classify_threat(self, threat_input: str, anomaly_score: float) -> tuple:
        """
        Classify threat based on content and anomaly score.
        Returns (classification, is_novel, confidence)
        """
        threat_lower = threat_input.lower()
        
        # Pattern matching for known threat types
        if "ransomware" in threat_lower:
            return ("Ransomware", False, 0.85)
        elif "phishing" in threat_lower or "spear-phishing" in threat_lower:
            return ("Phishing", False, 0.80)
        elif "ddos" in threat_lower or "denial of service" in threat_lower:
            return ("DDoS Attack", False, 0.75)
        elif "apt" in threat_lower or "advanced persistent threat" in threat_lower:
            return ("APT Attack", False, 0.82)
        elif "zero-day" in threat_lower or "0-day" in threat_lower:
            return ("Zero-Day Exploit", True, 0.88)
        elif anomaly_score > 0.8:
            return ("Novel Threat / Zero-Day", True, 0.85)
        elif anomaly_score > 0.6:
            return ("Unknown Malware Type", True, 0.70)
        else:
            return ("Suspicious Activity", False, 0.55)

    def _extract_features(self, threat_input: str) -> List[Dict]:
        """
        Extract behavioral features from threat input.
        """
        threat_lower = threat_input.lower()
        features = []
        
        # Check for common behavioral patterns
        behavioral_patterns = {
            "Process Injection": "injection|inject|process",
            "Lateral Movement": "lateral|movement|propagat|spread",
            "Data Exfiltration": "exfiltrat|steal|data|leak|extract",
            "Persistence Mechanism": "persist|autostart|registry|boot",
            "Anti-Analysis": "anti-analysis|anti-debug|evasion|obfuscat",
            "Command & Control": "c2|command|control|callback|beacon",
            "Privilege Escalation": "priv.*esc|escalat|admin|root|sudo"
        }
        
        for pattern_name, regex_pattern in behavioral_patterns.items():
            if re.search(regex_pattern, threat_lower):
                features.append({
                    "name": pattern_name,
                    "severity": "high",
                    "detected": True
                })
        
        return features

    def _generate_reasoning(self, classification: str, is_novel: bool, confidence: float, keywords: List[str]) -> str:
        """
        Generate detailed reasoning for the classification.
        """
        if is_novel:
            return f"Novel threat detected with {confidence*100:.0f}% confidence. Indicators: {', '.join(keywords[:3])}. No direct match to known threat signatures. Recommend immediate escalation and forensic analysis."
        else:
            return f"Classified as {classification} with {confidence*100:.0f}% confidence. Matches known threat patterns including: {', '.join(keywords[:3])}. Known mitigation strategies available."

    def format_output(self, result: Dict) -> Dict:
        """
        Format the anomaly detection result for reporting and collaboration.
        """
        return {
            "status": "analysis_complete",
            "classification": result["classification"],
            "novelty": "NOVEL" if result["novel"] else "KNOWN",
            "confidence": f"{result['confidence']*100:.0f}%",
            "anomaly_score": f"{result['anomaly_score']*100:.0f}%",
            "recommendation": result["recommendation"],
            "reasoning": result["similarity_reasoning"],
            "behavioral_features": result["features"],
            "indicators": result["matched_indicators"]
        }
