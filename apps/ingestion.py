import os
from flask import Flask, request, jsonify
import requests
app = Flask(__name__)

SERVICE_NAME = "ingestion-service"
SERVICE_URL = os.getenv("SERVICE_URL", "http://localhost:5001")

REGISTRY_URL = os.getenv(
    "REGISTRY_URL",
    "http://127.0.0.1:5050",
)

STORAGE_URL = os.getenv(
    "STORAGE_URL",
    "http://127.0.0.1:5002",
)

@app.route('/ingest', methods=['POST'])
def ingest():
	data = request.get_json()
	print("Received:", data)
	# Forward to storage
	try:
		res = requests.post(
			f"{STORAGE_URL}/store",
			json=data,
			timeout=5
		)
		if res.status_code == 200:
			return jsonify({"stored": True}), 200

		return jsonify({
			"stored": False,
			"error": "Storage did not confirm the write"
		}), res.status_code
	except Exception as e:
		return jsonify({"error": str(e)}), 500

def register():
	requests.post(f"{REGISTRY_URL}/register", 
	json={
		"name": SERVICE_NAME,
		"url": SERVICE_URL
	})

if __name__ == '__main__':
	register()
	app.run(host="0.0.0.0", port=5001)
