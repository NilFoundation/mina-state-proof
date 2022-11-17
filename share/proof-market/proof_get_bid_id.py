import requests
import json
import json
import sys
import os
import logging

secret = open(os.path.dirname(os.path.abspath(__file__)) + "/.secret", "r").read()
user = open(os.path.dirname(os.path.abspath(__file__)) + "/.user", "r").read()

def get(bid_id):
    url = 'http://try.dbms.nil.foundation/market/proof/bid_id/' + bid_id
    res = requests.get(url=url, auth=(user, secret))
    if res.status_code == 200:
            logging.info(f"Proof:\t {res.json()}")
            return res.json()
    else:
        logging.error(f"Error:\t {res.status_code} {res.reason}")
        return
	
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(message)s')
    if len(sys.argv) == 2:
        get(sys.argv[1])
    else:
        logging.error(f"Error:\t Invalid number of arguments")