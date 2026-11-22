import os
from flask import Flask, request, jsonify
import sqlite3
from pathlib import Path

app = Flask(__name__)
DB = os.getenv(
    "DB_PATH",
    str(Path(__file__).with_name("temp_data.db"))
)


def init_db():
	conn = sqlite3.connect(DB)
	c = conn.cursor()
	c.execute('''
		CREATE TABLE IF NOT EXISTS temperatures (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		device_id TEXT,
		temperature REAL,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	''')
	conn.commit()
	conn.close()

@app.route('/store', methods=['POST'])
def store():
	data = request.get_json()
	conn = sqlite3.connect(DB)
	c = conn.cursor()
	c.execute("INSERT INTO temperatures (device_id, temperature) VALUES (?, ?)",
		(data["device_id"], data["temperature"]))
	conn.commit()
	conn.close()
	return jsonify({"status": "stored"}), 200

@app.route('/stats', methods=['GET'])
def stats():
    conn = sqlite3.connect(DB)

    count, total = conn.execute(
        "SELECT COUNT(temperature), SUM(temperature) FROM temperatures"
    ).fetchone()

    conn.close()

    return jsonify({
        "measurements": count,
        "sum_temperature": total if total is not None else 0
    })

if __name__ == '__main__':
	init_db()
	app.run(host="0.0.0.0", port=5002)
