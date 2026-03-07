print("🔍 Testing imports...")

try:
    from agent1.agent1_interface import Agent1
    print("✅ Agent1 imported successfully")
except Exception as e:
    print("❌ Agent1 import failed:", e)

try:
    from mitre_mapper.mitre_engine import MITREMapper
    print("✅ MITREMapper imported successfully")
except Exception as e:
    print("❌ MITREMapper import failed:", e)

try:
    from agent2.agent.decision_engine import DecisionAgent
    print("✅ DecisionAgent imported successfully")
except Exception as e:
    print("❌ DecisionAgent import failed:", e)
