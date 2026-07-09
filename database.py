import sqlite3
import csv
import os
from datetime import datetime

DB_PATH = os.path.expanduser('~/usb-kiosk/logs/audit.db')

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS device_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        vid_pid TEXT,
        serial TEXT,
        event_type TEXT,
        result TEXT,
        reason TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS file_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        vid_pid TEXT,
        serial TEXT,
        filename TEXT,
        filepath TEXT,
        sha256 TEXT,
        engine TEXT,
        verdict TEXT,
        detection TEXT,
        action TEXT,
        error TEXT
    )''')
    conn.commit()
    conn.close()

def log_device_event(vid_pid, serial, event_type, result, reason=''):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('INSERT INTO device_events (timestamp,vid_pid,serial,event_type,result,reason) VALUES (?,?,?,?,?,?)',
              (datetime.utcnow().isoformat(), vid_pid, serial, event_type, result, reason))
    conn.commit()
    conn.close()

def log_file_event(vid_pid, serial, filename, filepath, sha256, engine, verdict, detection='', action='', error=''):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('INSERT INTO file_events (timestamp,vid_pid,serial,filename,filepath,sha256,engine,verdict,detection,action,error) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
              (datetime.utcnow().isoformat(), vid_pid, serial, filename, filepath, sha256, engine, verdict, detection, action, error))
    conn.commit()
    conn.close()

def get_all_file_events():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT * FROM file_events ORDER BY timestamp DESC')
    rows = c.fetchall()
    conn.close()
    return rows

def export_csv(output_path):
    rows = get_all_file_events()
    with open(output_path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['ID','Timestamp','VID:PID','Serial','Filename','Filepath','SHA256','Engine','Verdict','Detection','Action','Error'])
        writer.writerows(rows)
