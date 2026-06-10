import json
from typing import List, Dict, Any, Optional
from app.db_manager import db_engine

class HuntEngine:
    def __init__(self):
        self.db = db_engine

    def search(self, entity_type: str, query_params: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Perform structured hunts across different entities.
        Supported entities: 'assets', 'alerts', 'attack_chains', 'cases', 'mitre'
        """
        valid_entities = ['assets', 'alerts', 'attack_chains', 'cases']
        if entity_type not in valid_entities and entity_type != 'mitre':
            return []

        if entity_type == 'mitre':
            # MITRE is basically an aggregate query on alerts and attack chains
            return self._hunt_mitre(query_params)

        query_parts = []
        params = []
        
        # Build SQL dynamically based on parameters
        for key, value in query_params.items():
            if value is None or value == "":
                continue
            if key == 'ioc' and value.lower() in ['true', '1']:
                if entity_type == 'alerts':
                    query_parts.append("category LIKE ?")
                    params.append("%IOC%")
                continue

            if key == 'mitre':
                if entity_type == 'alerts':
                    query_parts.append("mitre_technique = ?")
                    params.append(value)
                elif entity_type == 'attack_chains':
                    query_parts.append("tactics_progression LIKE ?")
                    params.append(f"%{value}%")
                continue
                
            if key == 'tactic':
                if entity_type == 'alerts':
                    query_parts.append("mitre_tactic = ?")
                    params.append(value)
                elif entity_type == 'attack_chains':
                    query_parts.append("tactics_progression LIKE ?")
                    params.append(f"%{value}%")
                continue

            # Standard column matches
            query_parts.append(f"{key} = ?")
            params.append(value)

        where_clause = " AND ".join(query_parts) if query_parts else "1=1"
        sql = f"SELECT * FROM {entity_type} WHERE {where_clause} LIMIT 1000"

        with self.db.get_connection() as conn:
            cursor = conn.execute(sql, params)
            rows = cursor.fetchall()
            return [dict(row) for row in rows]

    def _hunt_mitre(self, params: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Aggregate view of MITRE tactics across the environment.
        """
        with self.db.get_connection() as conn:
            sql = """
                SELECT mitre_tactic as tactic, mitre_technique as technique, COUNT(*) as alert_count, COUNT(DISTINCT src_ip) as asset_count
                FROM alerts 
                WHERE mitre_technique IS NOT NULL AND mitre_technique != ''
                GROUP BY mitre_tactic, mitre_technique
                ORDER BY alert_count DESC
            """
            cursor = conn.execute(sql)
            return [dict(r) for r in cursor.fetchall()]

    def pivot(self, source_type: str, source_id: str, target_type: str) -> List[Dict[str, Any]]:
        """
        Pivots from one entity type to another using relationship keys.
        """
        with self.db.get_connection() as conn:
            if source_type == 'asset' and target_type == 'alerts':
                cursor = conn.execute("SELECT * FROM alerts WHERE src_ip = ? OR dst_ip = ?", (source_id, source_id))
                return [dict(r) for r in cursor.fetchall()]
                
            if source_type == 'asset' and target_type == 'attack_chains':
                cursor = conn.execute("SELECT * FROM attack_chains WHERE src_ip = ?", (source_id,))
                return [dict(r) for r in cursor.fetchall()]

            if source_type == 'alert' and target_type == 'asset':
                cursor = conn.execute("SELECT src_ip, dst_ip FROM alerts WHERE alert_id = ?", (source_id,))
                row = cursor.fetchone()
                if not row: return []
                ips = [ip for ip in [row['src_ip'], row['dst_ip']] if ip and ip not in ['N/A', 'Unknown']]
                if not ips: return []
                placeholders = ','.join(['?'] * len(ips))
                cursor = conn.execute(f"SELECT * FROM assets WHERE ip IN ({placeholders})", ips)
                return [dict(r) for r in cursor.fetchall()]

            if source_type == 'alert' and target_type == 'attack_chains':
                # alert_ids is JSON
                cursor = conn.execute("SELECT * FROM attack_chains WHERE alert_ids LIKE ?", (f"%\"{source_id}\"%",))
                return [dict(r) for r in cursor.fetchall()]

            if source_type == 'alert' and target_type == 'cases':
                cursor = conn.execute("SELECT c.* FROM cases c JOIN case_evidence ce ON c.case_id = ce.case_id WHERE ce.alert_id = ?", (source_id,))
                return [dict(r) for r in cursor.fetchall()]

            if source_type == 'case' and target_type == 'alerts':
                cursor = conn.execute("SELECT a.* FROM alerts a JOIN case_evidence ce ON a.alert_id = ce.alert_id WHERE ce.case_id = ?", (source_id,))
                return [dict(r) for r in cursor.fetchall()]
                
            if source_type == 'attack_chain' and target_type == 'alerts':
                cursor = conn.execute("SELECT alert_ids FROM attack_chains WHERE chain_id = ?", (source_id,))
                row = cursor.fetchone()
                if not row: return []
                try:
                    a_ids = json.loads(row['alert_ids'])
                    if not a_ids: return []
                    placeholders = ','.join(['?'] * len(a_ids))
                    cursor = conn.execute(f"SELECT * FROM alerts WHERE alert_id IN ({placeholders})", a_ids)
                    return [dict(r) for r in cursor.fetchall()]
                except:
                    return []

        return []

    def build_threat_graph(self) -> Dict[str, Any]:
        """
        Generates nodes and edges for D3/React Flow rendering.
        Extracts top assets, correlated chains, and high severity alerts.
        """
        nodes = []
        edges = []
        node_ids = set()

        def add_node(n_id, n_type, label, data=None):
            if n_id not in node_ids:
                nodes.append({"id": n_id, "type": n_type, "label": label, "data": data or {}})
                node_ids.add(n_id)
                
        def add_edge(src, dst, label=""):
            if src in node_ids and dst in node_ids:
                edges.append({"source": src, "target": dst, "label": label})

        with self.db.get_connection() as conn:
            # 1. Fetch active attack chains
            chains = [dict(r) for r in conn.execute("SELECT * FROM attack_chains LIMIT 50").fetchall()]
            for c in chains:
                c_id = c['chain_id']
                add_node(c_id, 'attack_chain', f"Chain {c_id[-4:]}", data={"tactics": c['tactics_progression']})
                
                # Add asset node
                src_ip = c['src_ip']
                if src_ip:
                    add_node(src_ip, 'asset', src_ip)
                    add_edge(src_ip, c_id, "source_of")

                # Parse alert IDs
                try:
                    alert_ids = json.loads(c['alert_ids'])
                    for a_id in alert_ids:
                        add_node(a_id, 'alert', f"Alert {a_id[-4:]}")
                        add_edge(c_id, a_id, "contains")
                except:
                    pass

            # 2. Fetch critical unchained alerts
            alerts = [dict(r) for r in conn.execute("SELECT * FROM alerts WHERE severity IN ('High', 'Critical') LIMIT 100").fetchall()]
            for a in alerts:
                a_id = a['alert_id']
                add_node(a_id, 'alert', a['category'], data={"severity": a['severity']})
                if a['src_ip'] and a['src_ip'] != 'N/A':
                    add_node(a['src_ip'], 'asset', a['src_ip'])
                    add_edge(a['src_ip'], a_id, "generated")

            # 3. Fetch cases and link to evidence
            cases = [dict(r) for r in conn.execute("SELECT * FROM cases WHERE status != 'Closed' LIMIT 20").fetchall()]
            for case in cases:
                case_id = case['case_id']
                add_node(case_id, 'case', case['title'])
                
                evidence = conn.execute("SELECT alert_id FROM case_evidence WHERE case_id = ?", (case_id,)).fetchall()
                for ev in evidence:
                    if ev['alert_id']:
                        add_node(ev['alert_id'], 'alert', f"Alert {ev['alert_id'][-4:]}")
                        add_edge(case_id, ev['alert_id'], "has_evidence")

        return {"nodes": nodes, "edges": edges}

hunt_engine = HuntEngine()
