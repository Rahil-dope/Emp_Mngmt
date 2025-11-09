import sqlite3
conn=sqlite3.connect('attendance.db')
cur=conn.cursor()
cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
print('tables:', cur.fetchall())
cur.execute("PRAGMA table_info('agent')")
print('agent info:', cur.fetchall())
conn.close()