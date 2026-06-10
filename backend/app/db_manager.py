import os
import gzip
import requests
import datetime

def download_and_extract(url, dest_path):
    print(f"[DBManager] Downloading {url}...")
    try:
        response = requests.get(url, stream=True, timeout=30)
        if response.status_code == 200:
            with gzip.open(response.raw, 'rb') as f_in:
                with open(dest_path, 'wb') as f_out:
                    f_out.write(f_in.read())
            print(f"[DBManager] Successfully extracted to {dest_path}")
            return True
        else:
            print(f"[DBManager] Failed to download {url} (Status: {response.status_code})")
            return False
    except Exception as e:
        print(f"[DBManager] Exception during download: {e}")
        return False

def get_previous_month(dt):
    first = dt.replace(day=1)
    prev = first - datetime.timedelta(days=1)
    return prev

def ensure_databases():
    temp_dir = os.path.join(os.getcwd(), "temp", "mmdb")
    os.makedirs(temp_dir, exist_ok=True)
    
    city_db_path = os.path.join(temp_dir, "dbip-city-lite.mmdb")
    asn_db_path = os.path.join(temp_dir, "dbip-asn-lite.mmdb")
    
    if os.path.exists(city_db_path) and os.path.exists(asn_db_path):
        print("[DBManager] Offline databases already exist.")
        return
        
    print("[DBManager] Offline databases missing. Initializing download...")
    
    now = datetime.datetime.now()
    prev = get_previous_month(now)
    months_to_try = [now, prev]
    
    city_success = os.path.exists(city_db_path)
    asn_success = os.path.exists(asn_db_path)
    
    for dt in months_to_try:
        ym = dt.strftime("%Y-%m")
        city_url = f"https://download.db-ip.com/free/dbip-city-lite-{ym}.mmdb.gz"
        asn_url = f"https://download.db-ip.com/free/dbip-asn-lite-{ym}.mmdb.gz"
        
        if not city_success:
            city_success = download_and_extract(city_url, city_db_path)
        if not asn_success:
            asn_success = download_and_extract(asn_url, asn_db_path)
            
        if city_success and asn_success:
            break

    if not city_success or not asn_success:
        print("[DBManager] CRITICAL WARNING: Failed to download one or more DB-IP databases.")

# ------------------------------------------------------------------------------
# Unified SQLite Database Engine
# ------------------------------------------------------------------------------
import sqlite3

class DatabaseEngine:
    def __init__(self, db_path: str = "temp/hexsniff_core.db"):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._init_db()

    def get_connection(self):
        conn = sqlite3.connect(self.db_path, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
        return conn

    def _init_db(self):
        with self.get_connection() as conn:
            conn.executescript('''
                -- Case Management Tables
                CREATE TABLE IF NOT EXISTS cases (
                    case_id TEXT PRIMARY KEY,
                    title TEXT,
                    status TEXT,
                    severity TEXT,
                    notes TEXT,
                    tags TEXT,
                    created_at REAL,
                    updated_at REAL
                );

                CREATE TABLE IF NOT EXISTS case_evidence (
                    evidence_id TEXT PRIMARY KEY,
                    case_id TEXT,
                    packet_id TEXT,
                    alert_id TEXT,
                    ioc TEXT,
                    mitre_technique TEXT,
                    mitre_tactic TEXT,
                    FOREIGN KEY(case_id) REFERENCES cases(case_id)
                );

                CREATE TABLE IF NOT EXISTS case_timeline (
                    event_id TEXT PRIMARY KEY,
                    case_id TEXT,
                    timestamp REAL,
                    event_type TEXT,
                    description TEXT,
                    FOREIGN KEY(case_id) REFERENCES cases(case_id)
                );
                
                CREATE INDEX IF NOT EXISTS idx_case_evidence_case_id ON case_evidence(case_id);
                CREATE INDEX IF NOT EXISTS idx_case_timeline_case_id ON case_timeline(case_id);

                -- Alerts & Correlation Tables
                CREATE TABLE IF NOT EXISTS alerts (
                    alert_id TEXT PRIMARY KEY,
                    timestamp REAL,
                    category TEXT,
                    severity TEXT,
                    message TEXT,
                    src_ip TEXT,
                    dst_ip TEXT,
                    proto TEXT,
                    mitre_technique TEXT,
                    mitre_tactic TEXT,
                    confidence INTEGER
                );

                CREATE TABLE IF NOT EXISTS attack_chains (
                    chain_id TEXT PRIMARY KEY,
                    src_ip TEXT,
                    start_time REAL,
                    last_update REAL,
                    tactics_progression TEXT,  -- JSON list of tactics
                    alert_ids TEXT,            -- JSON list of alert_ids
                    status TEXT                -- Open, Correlated, Resolved
                );

                -- Asset Inventory
                CREATE TABLE IF NOT EXISTS assets (
                    ip TEXT PRIMARY KEY,
                    mac TEXT,
                    first_seen REAL,
                    last_seen REAL,
                    open_ports TEXT,           -- JSON list of ports
                    os_guess TEXT,
                    risk_score INTEGER
                );
            ''')
            conn.commit()

# Singleton engine
db_engine = DatabaseEngine()

