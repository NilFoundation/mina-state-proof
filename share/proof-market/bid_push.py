import random
import sys
import requests
import os
import logging
import argparse

secret = open(os.path.dirname(os.path.abspath(__file__)) + "/.secret", "r").read()
user = open(os.path.dirname(os.path.abspath(__file__)) + "/.user", "r").read()

def push(data=None):
    if data is None:
        # some gibberish stuff
        if len(sys.argv) >= 2:
            public_input = sys.argv[1]
        else:
            public_input = '8690a3b1428829d4ac104b93468bf8495e79699c424aab7b1cf94e5f78b3bcc8'

        data = {"circuit_id": 2, 
                "sender": 'James',
                "wait_period": 1000, 
                'public_input': public_input,
                "cost": 0.5, 
                "eval_time": random.randint(5, 100),
                }

    url = 'http://try.dbms.nil.foundation/market/bid'
    res = requests.post(url=url, json=data, auth=(user, secret))
    if res.status_code != 200:
        logging.error(f"Error: {res.status_code} {res.reason}")
        return
    else:
        logging.info(f"Limit bid:\t {res.json()}")
        return res.json()

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(message)s')
    parser = argparse.ArgumentParser()
    parser.add_argument('--sender', help="Sender's identifier", default="James")
    parser.add_argument('--cost', help="Proof cost", default="0.5")
    args = parser.parse_args()
    data = {"circuit_id": 2, 
                "sender": args.sender,
                "wait_period": 1000,
                "cost": float(args.cost), 
                "eval_time": random.randint(5, 100),
                }
    push(data)
