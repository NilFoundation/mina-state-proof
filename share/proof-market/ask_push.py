import random
import sys
import requests
import os
import logging

secret = open(os.path.dirname(os.path.abspath(__file__)) + "/.secret", "r").read()
user = open(os.path.dirname(os.path.abspath(__file__)) + "/.user", "r").read()

def push(data=None):
    if data is None:
        data = {"circuit_id": 2, 
                "sender": 'James',
                "wait_period": 1000,
                "cost": 0.5, 
                "eval_time": random.randint(5, 100),
                }

    url = 'http://try.dbms.nil.foundation/market/ask'
    res = requests.post(url=url, json=data, auth=(user, secret))
    if res.status_code != 200:
        logging.error(f"Error: {res.status_code} {res.reason}")
        return
    else:
        logging.info(f"Limit ask:\t {res.json()}")
        return res.json()

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(message)s')
    push()