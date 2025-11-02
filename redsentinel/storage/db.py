# redsentinel/storage/db.py
import sqlite3, json, threading
from contextlib import closing

class ResultDB:
    def __init__(self, path="redsentinel_results.db"):
        self.path = path
        self._lock = threading.Lock()
        self._init()

    def _init(self):
        with closing(sqlite3.connect(self.path)) as conn:
            c = conn.cursor()
            c.execute("""CREATE TABLE IF NOT EXISTS results (
                id INTEGER PRIMARY KEY,
                target TEXT,
                module TEXT,
                timestamp TEXT,
                payload TEXT
            )""")
            conn.commit()

    def store(self, target, module, timestamp, payload: dict):
        with self._lock, closing(sqlite3.connect(self.path)) as conn:
            c = conn.cursor()
            c.execute("INSERT INTO results (target,module,timestamp,payload) VALUES (?,?,?,?)",
                      (target, module, timestamp, json.dumps(payload)))
            conn.commit()
