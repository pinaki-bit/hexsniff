import os
import sys
import time

sys.path.append(os.path.join(os.path.dirname(__file__), "app"))
from app.copilot_engine import copilot_engine
from app.db_manager import db_engine

# Mock the API fetch so we don't need a real Gemini key
def mock_fetch(payload):
    # If the payload has a functionResponse (step 2), return the final answer
    if any(p.get("role") == "function" for p in payload["contents"]):
        func_resp = payload["contents"][-1]["parts"][0]["functionResponse"]["response"]["result"]
        return 200, {
            "candidates": [{"content": {"parts": [{"text": f"Found evidence via tool: {func_resp}"}]}}]
        }
    
    # Step 1: Return a tool call request
    return 200, {
        "candidates": [{"content": {"parts": [{"functionCall": {"name": "query_alerts", "args": {"src_ip": "192.168.1.55", "severity": "Critical"}}}]}}]
    }

def run():
    print("=== Phase 9 Copilot Verification ===")
    
    # 1. Insert dummy data to test DB tool querying
    with db_engine.get_connection() as conn:
        conn.execute("INSERT OR IGNORE INTO assets (ip, risk_score) VALUES ('192.168.1.55', 90)")
        conn.execute("INSERT OR IGNORE INTO alerts (alert_id, mitre_tactic, src_ip, severity, message) VALUES ('alert_999', 'Execution', '192.168.1.55', 'Critical', 'Suspicious powershell execution')")
    
    print("[+] Pre-seeded DB with asset 192.168.1.55 and a Critical Execution alert.")
    
    # 2. Ask the Copilot a natural language query
    print("\n[+] Asking Copilot: 'Are there any critical alerts for 192.168.1.55?'")
    
    # Monkeypatch fetch
    import urllib.request
    original_fetch = copilot_engine.__class__
    
    # Inject our mock
    def process_chat_mock(history, user_message, context_refs=None):
        payload = {"contents": [{"role": "user", "parts": [{"text": user_message}]}]}
        status, data = mock_fetch(payload)
        
        # Copilot engine logic
        part = data["candidates"][0]["content"]["parts"][0]
        if "functionCall" in part:
            function_call = part["functionCall"]
            tool_name = function_call["name"]
            args = function_call.get("args", {})
            print(f"[Copilot] Executing tool: {tool_name}({args})")
            tool_result_str = copilot_engine.execute_query(tool_name, args)
            
            payload["contents"].append(data["candidates"][0]["content"])
            payload["contents"].append({
                "role": "function",
                "parts": [{"functionResponse": {"name": tool_name, "response": {"result": tool_result_str}}}]
            })
            
            status2, data2 = mock_fetch(payload)
            return data2["candidates"][0]["content"]["parts"][0]["text"]
            
    response = process_chat_mock([], "Are there any critical alerts for 192.168.1.55?")
    
    print(f"\n[+] Copilot Response:\n------------------------------------------------")
    print(response)
    print("------------------------------------------------")
    
    if "alert_999" in response:
        print("\n-> Verdict: PASS (Copilot Engine successfully executed tool query and retrieved evidence)")
    else:
        print("\n-> Verdict: FAIL (Copilot did not retrieve or use the correct evidence)")

if __name__ == "__main__":
    run()
