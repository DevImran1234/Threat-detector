"""
Agent 2 Main Entry Point
Can be used as standalone service or as part of pipeline
"""

import sys
import os

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.decision_engine import DecisionAgent
import json

def main():
    """Main entry point for standalone Agent 2"""
    print("🚀 Agent 2 - Decision and Response Agent")
    print("-" * 50)
    
    # Initialize agent
    agent = DecisionAgent()
    
    # Check if running in API mode or CLI mode
    if len(sys.argv) > 1 and sys.argv[1] == '--api':
        start_api(agent)
    else:
        run_cli(agent)

def run_cli(agent: DecisionAgent):
    """Run in command-line interface mode"""
    
    print("Interactive Mode - Enter alert data as JSON")
    print("Example: {'mitre_mapping': {'risk_score': 75, 'mitre_techniques': [...]}}")
    print("Type 'exit' to quit, 'history' to see past decisions")
    print("-" * 50)
    
    while True:
        try:
            user_input = input("\n📝 Enter alert JSON: ").strip()
            
            if not user_input:
                continue
            
            if user_input.lower() == 'exit':
                print("Goodbye!")
                break
            
            if user_input.lower() == 'history':
                history = agent.get_history()
                print(f"\n📊 Decision History ({len(history)} entries):")
                for i, entry in enumerate(history[-5:], 1):  # Show last 5
                    print(f"  {i}. Alert: {entry['alert_id']}, "
                          f"Actions: {len(entry['actions'])}, "
                          f"Policy: {entry['policy_used']}")
                continue
            
            # Parse JSON input
            try:
                alert_data = json.loads(user_input)
            except json.JSONDecodeError:
                print("❌ Invalid JSON. Please enter valid JSON.")
                continue
            
            # Make decision
            result = agent.decide(alert_data)
            
            # Print result
            print("\n✅ Decision Made:")
            print(f"  Alert ID: {result['alert_id']}")
            print(f"  Policy: {result['policy_used']}")
            print(f"  Priority: {result['priority']}")
            print(f"  Actions ({len(result['actions'])}):")
            for i, action in enumerate(result['actions'], 1):
                print(f"    {i}. {action}")
            
            if result.get('execution_results'):
                print(f"  Execution: {len(result['execution_results'])} actions executed")
            
        except KeyboardInterrupt:
            print("\n\nExiting...")
            break
        except Exception as e:
            print(f"❌ Error: {e}")

def start_api(agent: DecisionAgent):
    """Start FastAPI server for Agent 2"""
    try:
        from fastapi import FastAPI, HTTPException
        import uvicorn
        
        app = FastAPI(title="Agent 2 - Decision API")
        
        @app.get("/")
        async def root():
            return {
                "service": "Agent 2 Decision Engine",
                "status": "running",
                "version": "1.0.0"
            }
        
        @app.post("/decide")
        async def decide(alert_data: dict):
            """Make decision for alert"""
            try:
                result = agent.decide(alert_data)
                return result
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        @app.get("/history")
        async def get_history(limit: int = 10):
            """Get decision history"""
            history = agent.get_history()
            return history[-limit:] if limit > 0 else history
        
        print("Starting API server on http://127.0.0.1:8001")
        print("Endpoints:")
        print("  GET  /         - Health check")
        print("  POST /decide   - Make decision")
        print("  GET  /history  - Get decision history")
        
        uvicorn.run(app, host="127.0.0.1", port=8001)
        
    except ImportError:
        print("❌ FastAPI not installed. Install with: pip install fastapi uvicorn")
        print("Running in CLI mode instead...")
        run_cli(agent)

if __name__ == "__main__":
    main()