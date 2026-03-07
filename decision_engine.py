"""
Agent 2: Decision and Response Agent
Makes decisions based on MITRE-enriched alerts
"""

import json
import yaml
import os
from typing import Dict, List, Any
from datetime import datetime

class DecisionAgent:
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.policies = self.load_policies()
        self.response_history = []
        
        # Response action implementations
        self.action_implementations = {
            'isolate_endpoint': self.isolate_endpoint,
            'block_ip': self.block_ip,
            'quarantine_file': self.quarantine_file,
            'alert_soc': self.alert_soc,
            'collect_forensics': self.collect_forensics,
            'block_command_line': self.block_command_line,
            'increase_monitoring': self.increase_monitoring,
            'kill_process': self.kill_process,
            'update_firewall': self.update_firewall,
            'create_incident': self.create_incident,
            'monitor_only': self.monitor_only
        }
        
        print("✅ Decision Agent initialized")
    
    def load_policies(self) -> Dict:
        """Load response policies from policies directory"""
        policies = {}
        policy_dir = self.config.get('policy_path', 'policies/')
        
        if not os.path.exists(policy_dir):
            print(f"⚠️ Policy directory not found: {policy_dir}")
            return policies
        
        # Load YAML policies
        for file in os.listdir(policy_dir):
            if file.endswith('.yaml') or file.endswith('.yml'):
                try:
                    with open(os.path.join(policy_dir, file), 'r') as f:
                        policy_name = file.split('.')[0]
                        policies[policy_name] = yaml.safe_load(f)
                except Exception as e:
                    print(f"Error loading policy {file}: {e}")
        
        # Load JSON policies
        for file in os.listdir(policy_dir):
            if file.endswith('.json'):
                try:
                    with open(os.path.join(policy_dir, file), 'r') as f:
                        policy_name = file.split('.')[0]
                        policies[policy_name] = json.load(f)
                except Exception as e:
                    print(f"Error loading policy {file}: {e}")
        
        print(f"Loaded {len(policies)} policies")
        return policies
    
    def decide(self, alert_data: Dict) -> Dict:
        """
        Make response decisions based on alert data
        
        Args:
            alert_data: Dictionary containing alert information
            
        Returns:
            Dictionary with response decisions
        """
        alert_id = alert_data.get('alert_id', 'unknown')
        
        print(f"🔍 Analyzing alert {alert_id}...")
        
        # Extract key information
        mitre_techs = alert_data.get('mitre_mapping', {}).get('mitre_techniques', [])
        risk_score = alert_data.get('mitre_mapping', {}).get('risk_score', 0)
        severity = alert_data.get('classification', {}).get('severity', 'medium')
        iocs = alert_data.get('classification', {}).get('iocs', [])
        
        # Determine appropriate policy
        policy = self.select_policy(risk_score, severity, mitre_techs)
        
        # Get actions from policy
        actions = self.get_actions_from_policy(policy, alert_data)
        
        # Filter actions based on available implementations
        available_actions = []
        for action in actions:
            if action in self.action_implementations:
                available_actions.append(action)
            else:
                print(f"⚠️ Action not implemented: {action}")
        
        # Create response plan
        response_plan = {
            'alert_id': alert_id,
            'timestamp': datetime.now().isoformat(),
            'policy_used': policy,
            'actions': available_actions,
            'priority': self.calculate_priority(risk_score, severity),
            'execution_plan': self.create_execution_plan(available_actions),
            'context': {
                'risk_score': risk_score,
                'severity': severity,
                'mitre_techniques': [t['technique_id'] for t in mitre_techs],
                'ioc_count': len(iocs)
            }
        }
        
        # Execute actions if auto-execute is enabled
        auto_execute = self.config.get('auto_execute', False)
        if auto_execute and available_actions:
            execution_results = self.execute_actions(response_plan)
            response_plan['execution_results'] = execution_results
            response_plan['status'] = 'executed'
        else:
            response_plan['status'] = 'pending'
            response_plan['execution_results'] = []
        
        # Record in history
        self.response_history.append(response_plan)
        
        return response_plan
    
    def select_policy(self, risk_score: float, severity: str, 
                     mitre_techs: List[Dict]) -> str:
        """Select appropriate response policy"""
        
        # Default policy
        if risk_score >= 80:
            return 'critical'
        elif risk_score >= 60:
            return 'high'
        elif risk_score >= 40:
            return 'medium'
        elif risk_score >= 20:
            return 'low'
        else:
            return 'info'
    
    def get_actions_from_policy(self, policy_name: str, alert_data: Dict) -> List[str]:
        """Get actions from policy with context-aware adjustments"""
        
        # Default actions if policy not found
        default_actions = {
            'critical': ['isolate_endpoint', 'alert_soc', 'collect_forensics'],
            'high': ['block_ip', 'increase_monitoring', 'alert_soc'],
            'medium': ['monitor_only', 'create_incident'],
            'low': ['monitor_only'],
            'info': ['monitor_only']
        }
        
        # Get policy-specific actions
        if policy_name in self.policies:
            actions = self.policies[policy_name].get('actions', [])
        else:
            actions = default_actions.get(policy_name, ['monitor_only'])
        
        # Adjust actions based on MITRE techniques
        mitre_techs = alert_data.get('mitre_mapping', {}).get('mitre_techniques', [])
        for tech in mitre_techs:
            tech_id = tech.get('technique_id', '')
            
            # Add technique-specific actions
            if tech_id.startswith('T1059'):  # Command execution
                actions.append('block_command_line')
                actions.append('kill_process')
            elif tech_id.startswith('T1071'):  # C2
                actions.append('block_ip')
                actions.append('update_firewall')
            elif tech_id.startswith('T1027'):  # Obfuscation
                actions.append('collect_forensics')
        
        # Remove duplicates and ensure monitor_only is last if present
        unique_actions = []
        for action in actions:
            if action not in unique_actions:
                unique_actions.append(action)
        
        # Move monitor_only to end if it exists
        if 'monitor_only' in unique_actions:
            unique_actions.remove('monitor_only')
            unique_actions.append('monitor_only')
        
        return unique_actions
    
    def calculate_priority(self, risk_score: float, severity: str) -> int:
        """Calculate priority (1=highest, 5=lowest)"""
        if risk_score >= 80 or severity == 'critical':
            return 1
        elif risk_score >= 60 or severity == 'high':
            return 2
        elif risk_score >= 40 or severity == 'medium':
            return 3
        elif risk_score >= 20 or severity == 'low':
            return 4
        else:
            return 5
    
    def create_execution_plan(self, actions: List[str]) -> List[Dict]:
        """Create step-by-step execution plan"""
        plan = []
        order = 1
        
        for action in actions:
            plan.append({
                'step': order,
                'action': action,
                'description': self.get_action_description(action),
                'estimated_time': self.get_action_time_estimate(action),
                'status': 'pending',
                'timestamp': None,
                'result': None
            })
            order += 1
        
        return plan
    
    def get_action_description(self, action: str) -> str:
        """Get human-readable description for action"""
        descriptions = {
            'isolate_endpoint': 'Isolate affected endpoint from network',
            'block_ip': 'Block malicious IP address in firewall',
            'quarantine_file': 'Quarantine suspicious file',
            'alert_soc': 'Send alert to Security Operations Center',
            'collect_forensics': 'Collect forensic evidence from endpoint',
            'block_command_line': 'Block command-line execution',
            'increase_monitoring': 'Increase monitoring on affected system',
            'kill_process': 'Terminate malicious process',
            'update_firewall': 'Update firewall rules',
            'create_incident': 'Create incident ticket',
            'monitor_only': 'Monitor without taking action'
        }
        return descriptions.get(action, 'Unknown action')
    
    def get_action_time_estimate(self, action: str) -> int:
        """Get estimated time in seconds for action"""
        time_estimates = {
            'isolate_endpoint': 30,
            'block_ip': 5,
            'quarantine_file': 10,
            'alert_soc': 2,
            'collect_forensics': 300,
            'block_command_line': 5,
            'increase_monitoring': 60,
            'kill_process': 3,
            'update_firewall': 15,
            'create_incident': 30,
            'monitor_only': 1
        }
        return time_estimates.get(action, 10)
    
    def execute_actions(self, response_plan: Dict) -> List[Dict]:
        """Execute the response actions"""
        results = []
        
        for step in response_plan['execution_plan']:
            action = step['action']
            
            try:
                # Execute action
                if action in self.action_implementations:
                    result = self.action_implementations[action](response_plan)
                else:
                    result = {'success': False, 'error': 'Action not implemented'}
                
                # Update step
                step['status'] = 'completed' if result.get('success') else 'failed'
                step['timestamp'] = datetime.now().isoformat()
                step['result'] = result
                
                results.append({
                    'action': action,
                    'success': result.get('success', False),
                    'result': result,
                    'timestamp': step['timestamp']
                })
                
                print(f"  ✅ Executed: {action}")
                
            except Exception as e:
                step['status'] = 'error'
                step['timestamp'] = datetime.now().isoformat()
                step['result'] = {'success': False, 'error': str(e)}
                
                results.append({
                    'action': action,
                    'success': False,
                    'error': str(e),
                    'timestamp': step['timestamp']
                })
                
                print(f"  ❌ Failed: {action} - {e}")
        
        return results
    
    # Action implementations (stubs - integrate with your systems)
    
    def isolate_endpoint(self, alert_data: Dict) -> Dict:
        """Isolate endpoint from network"""
        # TODO: Implement actual isolation logic
        return {'success': True, 'message': 'Endpoint isolated'}
    
    def block_ip(self, alert_data: Dict) -> Dict:
        """Block IP address"""
        # TODO: Implement actual blocking logic
        return {'success': True, 'message': 'IP blocked'}
    
    def quarantine_file(self, alert_data: Dict) -> Dict:
        """Quarantine suspicious file"""
        # TODO: Implement actual quarantine logic
        return {'success': True, 'message': 'File quarantined'}
    
    def alert_soc(self, alert_data: Dict) -> Dict:
        """Alert Security Operations Center"""
        # TODO: Implement actual alerting logic
        return {'success': True, 'message': 'SOC alerted'}
    
    def collect_forensics(self, alert_data: Dict) -> Dict:
        """Collect forensic evidence"""
        # TODO: Implement actual forensics collection
        return {'success': True, 'message': 'Forensics collected'}
    
    def block_command_line(self, alert_data: Dict) -> Dict:
        """Block command-line execution"""
        # TODO: Implement actual blocking logic
        return {'success': True, 'message': 'Command line blocked'}
    
    def increase_monitoring(self, alert_data: Dict) -> Dict:
        """Increase monitoring"""
        # TODO: Implement actual monitoring increase
        return {'success': True, 'message': 'Monitoring increased'}
    
    def kill_process(self, alert_data: Dict) -> Dict:
        """Kill malicious process"""
        # TODO: Implement actual process termination
        return {'success': True, 'message': 'Process terminated'}
    
    def update_firewall(self, alert_data: Dict) -> Dict:
        """Update firewall rules"""
        # TODO: Implement actual firewall update
        return {'success': True, 'message': 'Firewall updated'}
    
    def create_incident(self, alert_data: Dict) -> Dict:
        """Create incident ticket"""
        # TODO: Implement actual incident creation
        return {'success': True, 'message': 'Incident created'}
    
    def monitor_only(self, alert_data: Dict) -> Dict:
        """Monitor only"""
        return {'success': True, 'message': 'Monitoring enabled'}
    
    def get_history(self) -> List[Dict]:
        """Get response history"""
        return self.response_history

# Test the agent
if __name__ == "__main__":
    agent = DecisionAgent()
    
    test_alert = {
        'alert_id': 'TEST-001',
        'mitre_mapping': {
            'mitre_techniques': [
                {'technique_id': 'T1059.001', 'name': 'PowerShell'}
            ],
            'risk_score': 85
        },
        'classification': {
            'severity': 'critical',
            'iocs': [
                {'type': 'ip', 'value': '192.168.1.100'}
            ]
        }
    }
    
    result = agent.decide(test_alert)
    print(f"\nDecision Result:")
    print(f"  Alert ID: {result['alert_id']}")
    print(f"  Policy: {result['policy_used']}")
    print(f"  Actions: {result['actions']}")
    print(f"  Priority: {result['priority']}")