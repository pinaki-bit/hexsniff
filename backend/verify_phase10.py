import os
import sys
import time
import json

sys.path.append(os.path.join(os.path.dirname(__file__), "app"))
from app.hunt_engine import hunt_engine
from app.db_manager import db_engine

def stress_test():
    print("=== Phase 10: Threat Hunting Validation ===")
    
    # 1. Verification of real records
    print("\n--- Forensic Verification ---")
    mitre_res = hunt_engine.search("mitre", {})
    print(f"[*] MITRE Aggregation returned {len(mitre_res)} tactics")
    
    if mitre_res:
        tactic = mitre_res[0].get('tactic')
        print(f"[*] Pivoting to alerts for tactic: {tactic}")
        alerts = hunt_engine.search("alerts", {"tactic": tactic})
        print(f"    -> Found {len(alerts)} evidence alerts.")
        
        if alerts:
            src_ip = alerts[0].get('src_ip')
            print(f"[*] Pivoting to assets for IP: {src_ip}")
            assets = hunt_engine.search("assets", {"ip": src_ip})
            print(f"    -> Found {len(assets)} asset records.")

    # 2. Stress Testing
    print("\n--- Stress Testing ---")
    sizes = [10000, 50000, 100000]
    
    with db_engine.get_connection() as conn:
        for size in sizes:
            print(f"[*] Simulating {size} evidence records (in memory)...")
            # Insert fake records just for stress test benchmark, inside a transaction
            try:
                conn.execute("BEGIN TRANSACTION")
                # Fast insertion
                records = [(f"hunt-test-{i}", f"10.0.0.{i%255}", "192.168.1.1", "Test Category", "High") for i in range(size)]
                conn.executemany("INSERT INTO alerts (alert_id, src_ip, dst_ip, category, severity) VALUES (?, ?, ?, ?, ?)", records)
                
                # Benchmark search
                t0 = time.time()
                res = conn.execute("SELECT COUNT(*) FROM alerts WHERE severity = 'High' AND src_ip LIKE '10.0.0.%'").fetchone()
                latency = time.time() - t0
                print(f"    -> Indexed Search Latency: {latency*1000:.2f}ms")
                
                # Rollback to keep database clean
                conn.execute("ROLLBACK")
                print("    -> Database clean (rollback successful)")
            except Exception as e:
                conn.execute("ROLLBACK")
                print(f"    -> Error: {e}")

    print("\n--- Graph Rendering Benchmark ---")
    t0 = time.time()
    graph = hunt_engine.build_threat_graph()
    latency = time.time() - t0
    nodes = len(graph.get('nodes', []))
    edges = len(graph.get('edges', []))
    print(f"[*] Graph generated {nodes} nodes and {edges} edges in {latency*1000:.2f}ms")
    print("=== Verification Complete ===")

if __name__ == "__main__":
    stress_test()
