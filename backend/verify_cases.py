import os
import time
import sqlite3
import json
from fastapi.testclient import TestClient
from app.main import app
from app.case_manager import CaseManager

client = TestClient(app)

results = {}

def get_db_schema():
    db_path = os.path.abspath("temp/hexsniff_cases.db")
    results["db_path"] = db_path
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    tables = cursor.execute("SELECT name, sql FROM sqlite_master WHERE type='table'").fetchall()
    schema_info = {}
    for table in tables:
        schema_info[table[0]] = table[1]
        
    indexes = cursor.execute("SELECT name, sql FROM sqlite_master WHERE type='index'").fetchall()
    for idx in indexes:
        schema_info[idx[0]] = idx[1]
        
    results["db_schema"] = schema_info
    conn.close()

def test_api():
    api_results = []
    
    # POST
    post_res = client.post("/api/cases", json={"title": "API Test Case", "status": "Open", "severity": "High"})
    api_results.append({"method": "POST", "endpoint": "/api/cases", "status": post_res.status_code, "request": '{"title": "API Test Case", "status": "Open", "severity": "High"}', "response": post_res.json()})
    case_id = post_res.json()["case_id"]
    
    # GET list
    get_list = client.get("/api/cases")
    api_results.append({"method": "GET", "endpoint": "/api/cases", "status": get_list.status_code, "request": "", "response": get_list.json()})
    
    # GET single
    get_single = client.get(f"/api/cases/{case_id}")
    api_results.append({"method": "GET", "endpoint": f"/api/cases/{case_id}", "status": get_single.status_code, "request": "", "response": get_single.json()})
    
    # PUT
    put_res = client.put(f"/api/cases/{case_id}", json={"status": "Closed"})
    api_results.append({"method": "PUT", "endpoint": f"/api/cases/{case_id}", "status": put_res.status_code, "request": '{"status": "Closed"}', "response": put_res.json()})
    
    # DELETE
    del_res = client.delete(f"/api/cases/{case_id}")
    api_results.append({"method": "DELETE", "endpoint": f"/api/cases/{case_id}", "status": del_res.status_code, "request": "", "response": del_res.json()})
    
    results["api_test"] = api_results

def test_persistence():
    # Create Case A
    post_res = client.post("/api/cases", json={"title": "Case A", "status": "Open", "severity": "High", "tags": "Test,Persist"})
    case_id = post_res.json()["case_id"]
    
    client.put(f"/api/cases/{case_id}", json={"notes": "Some important notes", "status": "In Progress"})
    
    # Simulate restart by instantiating a new CaseManager
    cm = CaseManager()
    persisted_case = cm.get_case(case_id)
    
    results["persistence"] = persisted_case

def test_evidence_link():
    cm = CaseManager()
    case = cm.create_case("EV_TEST_CASE", "Evidence Test")
    
    evidence = {
        "packet_id": "pkt_123",
        "alert_id": "alert_456",
        "ioc": "192.168.1.100",
        "mitre_technique": "T1059"
    }
    cm.add_evidence("EV_TEST_CASE", evidence)
    
    case = cm.get_case("EV_TEST_CASE")
    results["evidence"] = case["evidence"]

def test_timeline():
    cm = CaseManager()
    case = cm.create_case("TL_TEST_CASE", "Timeline Test")
    cm.update_case("TL_TEST_CASE", {"status": "In Progress"})
    cm.update_case("TL_TEST_CASE", {"severity": "Critical"})
    cm.update_case("TL_TEST_CASE", {"notes": "Updated note"})
    cm.add_evidence("TL_TEST_CASE", {"packet_id": "pkt_1"})
    
    case = cm.get_case("TL_TEST_CASE")
    results["timeline"] = case["timeline"]

def test_autosave_latency():
    cm = CaseManager()
    case = cm.create_case("LATENCY_TEST", "Latency")
    
    start = time.time()
    cm.update_case("LATENCY_TEST", {"notes": "Performance test"})
    end = time.time()
    
    results["latency_ms"] = (end - start) * 1000

def test_load():
    cm = CaseManager()
    
    # 100 cases
    start = time.time()
    for i in range(100):
        cm.create_case(f"LOAD_100_{i}", f"Load 100 {i}")
    results["load_100_create_ms"] = (time.time() - start) * 1000
    
    start = time.time()
    cm.list_cases()
    results["load_100_query_ms"] = (time.time() - start) * 1000
    
    start = time.time()
    for i in range(100):
        cm.update_case(f"LOAD_100_{i}", {"status": "Closed"})
    results["load_100_update_ms"] = (time.time() - start) * 1000
    
    # 1000 cases
    start = time.time()
    for i in range(1000):
        cm.create_case(f"LOAD_1000_{i}", f"Load 1000 {i}")
    results["load_1000_create_ms"] = (time.time() - start) * 1000
    
    start = time.time()
    cm.list_cases()
    results["load_1000_query_ms"] = (time.time() - start) * 1000
    
    start = time.time()
    for i in range(1000):
        cm.update_case(f"LOAD_1000_{i}", {"status": "Closed"})
    results["load_1000_update_ms"] = (time.time() - start) * 1000

get_db_schema()
test_api()
test_persistence()
test_evidence_link()
test_timeline()
test_autosave_latency()
test_load()

with open("verification_results.json", "w") as f:
    json.dump(results, f, indent=4)
print("Verification complete.")
