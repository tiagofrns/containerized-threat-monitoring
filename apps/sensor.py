import requests
import time
import random
import os


DEVICE_ID = "sensor-001"

INGESTION_URL = os.getenv(
    "INGESTION_URL", "http://127.0.0.1:5001/ingest"
)

def send_temp():
	while True:
		temp = round(random.uniform(20.0, 30.0), 2)
		payload = {"device_id": DEVICE_ID, "temperature": temp}
		try:
			requests.post(f"{INGESTION_URL}", json=payload)
			print("Sent:", payload)
		except Exception as e:
			print("Error:", e)
		time.sleep(5)

if __name__ == '__main__':
	send_temp()
