import sqlite3

DB_NAME = "memory_forensics.db"

def get_db_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 1. Processes Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS processes (
            pid INTEGER PRIMARY KEY, ppid INTEGER, name TEXT, 
            offset TEXT, threads INTEGER, handles INTEGER, 
            vt_status TEXT DEFAULT 'Unchecked', vt_malicious_count INTEGER DEFAULT 0
        )
    ''')
    
    # 2. IOCs Table (டயக்ராமில் உள்ளபடி IPs, Domains, Registry Keys)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS iocs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT, value TEXT, description TEXT
        )
    ''')
    
    # 3. MITRE & Timeline Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS timeline (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT, event_type TEXT, description TEXT, mitre_technique TEXT
        )
    ''')
    
    conn.commit()
    conn.close()
    print("[+] Database Updated with Architecture Schema.")

if __name__ == "__main__":
    init_db()