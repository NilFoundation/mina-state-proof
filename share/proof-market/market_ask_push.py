import random
import sys
import requests
import json
import logging
import os

secret = open(os.path.dirname(os.path.abspath(__file__)) + "/.secret", "r").read()
user = open(os.path.dirname(os.path.abspath(__file__)) + "/.user", "r").read()

def push(data=None):
	if data is None:
		data = {"cost": random.randint(5, 100), 
				"sender": hex(random.randint(10 ** 40, 10 ** 41)),
				"eval_time": random.randint(100, 10000), 
				"circuit_id": 2, 
				"wait_period": random.randint(100, 10000),}
	url = 'http://try.dbms.nil.foundation/market/market_ask'
	res = requests.post(url=url, json=data, auth=(user, secret))
	if res.status_code == 200:
		logging.info(f"Market ask:\t {res.json()}")
		# return json.loads(res.json())
		return res.json()
	elif res.status_code == 204:
		logging.warning(f"No bids found")
		return None
	else:
		logging.error(f"Error: {res.status_code} {res.reason}")
		logging.error(f"Error: {res.json()}")
		return
	
if __name__ == "__main__":
	logging.basicConfig(level=logging.INFO, format='%(message)s')
	push()
