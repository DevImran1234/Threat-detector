"""
Main Orchestrator for MITRE Security Pipeline
Coordinates Agent 1 → MITRE Mapper → Agent 2
"""

import os
import time
import json
import yaml
from typing import Dict, List, Optional
from datetime import datetime
import hashlib

class MITREOrchestrator:
    def __init__(self, config_file: str = "config.yaml"):
        self.config = self.load_config(config_file)
        self.stats = {
            "total_processed": 0,
            "mitre_detections": 0,
            "start_time": time.time(),
            "processing_times": []
        }
        
        # Import agents (lazy loading)
        self.agent1 = None
        self.mitre_mapper = None
        self.agent2 = None
        
        print("MITRE Security Pipeline Orchestrator initialized")
    
    def load_config(self, config_file: str) -> Dict:
        """Load configuration from YAML file"""
        try:
            with open(config_file, 'r') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            print(f"Warning: Config file {config_file} not found, using defaults")
            return {}
    
    def initialize_agents(self):
        """Lazy initialization of agents"""
        if self.agent1 is None:
            from agent1_interface import Agent1
            self.agent1 = Agent1()
            print("✅ Agent 1 initialized")
        
        if self.mitre_mapper is None:
            from mitre_engine import MITREMapper
            self.mitre_mapper = MITREMapper(self.config.get('mitre', {}))
            print("✅ MITRE Mapper initialized")
        
        if self.agent2 is None:
            from decision_engine import DecisionAgent
            self.agent2 = DecisionAgent(self.config.get('agent2', {}))
            print("✅ Agent 2 initialized")
    
    def process_single_log(self, log_text: str) -> Dict:
        """Process a single log through the entire pipeline"""
        start_time = time.time()
        
        # Initialize agents if needed
        self.initialize_agents()
        
        # Generate unique ID for this log
        log_id = self.generate_log_id(log_text)
        
        print(f"\n{'='*60}")
        print(f"Processing Log ID: {log_id}")
        print(f"Log: {log_text[:150]}..." if len(log_text) > 150 else f"Log: {log_text}")
        print(f"{'='*60}")
        
        # Step 1: Agent 1 - Log Classification
        print("🔍 [Step 1/3] Agent 1 - Classifying log...")
        agent1_result = self.agent1.classify(log_text)
        print(f"   → Classification: {agent1_result['label']} "
              f"(Confidence: {agent1_result['confidence']:.2%})")
        
        # Step 2: MITRE Mapping
        print("🎯 [Step 2/3] MITRE Mapper - Mapping to ATT&CK...")
        mitre_result = self.mitre_mapper.map(
            log_text=log_text,
            classification=agent1_result['label'],
            confidence=agent1_result['confidence'],
            iocs=agent1_result.get('iocs', [])
        )
        
        if mitre_result['mitre_techniques']:
            self.stats["mitre_detections"] += 1
            print(f"   → Detected {len(mitre_result['mitre_techniques'])} MITRE technique(s)")
            for tech in mitre_result['mitre_techniques'][:3]:  # Show first 3
                print(f"     • {tech['technique_id']}: {tech['name']}")
            if len(mitre_result['mitre_techniques']) > 3:
                print(f"     • ... and {len(mitre_result['mitre_techniques']) - 3} more")
        else:
            print("   → No MITRE techniques detected")
        
        print(f"   → Risk Score: {mitre_result['risk_score']:.1f}/100")
        
        # Step 3: Agent 2 - Decision & Response
        print("🤖 [Step 3/3] Agent 2 - Determining response...")
        alert_data = {
            "alert_id": f"ALT-{log_id}",
            "timestamp": datetime.now().isoformat(),
            "log_text": log_text[:500],  # Truncate for storage
            "classification": agent1_result,
            "mitre_mapping": mitre_result,
            "log_id": log_id
        }
        
        agent2_result = self.agent2.decide(alert_data)
        print(f"   → {len(agent2_result['actions'])} response action(s) determined")
        if agent2_result['actions']:
            for i, action in enumerate(agent2_result['actions'][:3], 1):
                print(f"     {i}. {action}")
        
        # Calculate processing time
        processing_time = time.time() - start_time
        self.stats["processing_times"].append(processing_time)
        self.stats["total_processed"] += 1
        
        print(f"\n⏱️ Processing time: {processing_time:.3f} seconds")
        print(f"{'='*60}")
        
        # Return complete result
        result = {
            "pipeline_run_id": f"PIPE-{int(time.time())}",
            "timestamp": datetime.now().isoformat(),
            "log_id": log_id,
            "log_preview": log_text[:200],
            "processing_time": processing_time,
            
            "agent1": agent1_result,
            "mitre": mitre_result,
            "agent2": agent2_result,
            
            "summary": {
                "threat_level": self.get_threat_level(mitre_result['risk_score']),
                "primary_technique": mitre_result['mitre_techniques'][0]['technique_id'] 
                                    if mitre_result['mitre_techniques'] else "None",
                "immediate_action": agent2_result['actions'][0] 
                                  if agent2_result['actions'] else "Monitor",
                "requires_attention": mitre_result['risk_score'] > 
                                    self.config.get('mitre', {}).get('risk_thresholds', {})
                                    .get('medium', 40)
            }
        }
        
        # Save result if configured
        if self.config.get('output', {}).get('save_results', True):
            self.save_result(result)
        
        return result
    
    def generate_log_id(self, log_text: str) -> str:
        """Generate unique ID for log"""
        # Use hash of log text and timestamp
        hash_input = f"{log_text}_{time.time()}"
        hash_obj = hashlib.md5(hash_input.encode())
        return hash_obj.hexdigest()[:8]  # First 8 chars
    
    def get_threat_level(self, risk_score: float) -> str:
        """Convert risk score to threat level"""
        thresholds = self.config.get('mitre', {}).get('risk_thresholds', {})
        
        if risk_score >= thresholds.get('critical', 80):
            return "CRITICAL"
        elif risk_score >= thresholds.get('high', 60):
            return "HIGH"
        elif risk_score >= thresholds.get('medium', 40):
            return "MEDIUM"
        elif risk_score >= thresholds.get('low', 20):
            return "LOW"
        else:
            return "INFO"
    
    def save_result(self, result: Dict):
        """Save result to output file"""
        output_dir = self.config.get('output', {}).get('output_dir', 'output')
        os.makedirs(output_dir, exist_ok=True)
        
        filename = f"{output_dir}/alert_{result['log_id']}.json"
        with open(filename, 'w') as f:
            json.dump(result, f, indent=2, default=str)
    
    def get_statistics(self) -> Dict:
        """Get pipeline statistics"""
        if not self.stats["processing_times"]:
            avg_time = 0
        else:
            avg_time = sum(self.stats["processing_times"]) / len(self.stats["processing_times"])
        
        return {
            "total_processed": self.stats["total_processed"],
            "mitre_detections": self.stats["mitre_detections"],
            "avg_time": avg_time,
            "uptime": time.time() - self.stats["start_time"]
        }
    
    def batch_process(self, logs: List[str]) -> List[Dict]:
        """Process multiple logs"""
        results = []
        for i, log in enumerate(logs, 1):
            print(f"\nProcessing {i}/{len(logs)}...")
            try:
                result = self.process_single_log(log)
                results.append(result)
            except Exception as e:
                print(f"Error processing log {i}: {e}")
                continue
        return results

# Quick test function
if __name__ == "__main__":
    import os
    
    # Test the orchestrator
    orchestrator = MITREOrchestrator()
    
    test_logs = [
        "powershell.exe -enc SQBFAFgAIAAkAGkAbgBwAHUAdAAgAD0AIAAkAGMAaABvAGkAYwBlADsAIABpAGUAeAAgACQAaQBuAHAAdQB0AA==",
        "User created scheduled task via schtasks /create /tn 'MaliciousTask'",
        "Connection attempt to 192.168.1.100:4444 from internal host",
        "Registry modification at HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\malware"
    ]
    
    for log in test_logs:
        result = orchestrator.process_single_log(log)
        print(f"\nSummary: {result['summary']}\n")