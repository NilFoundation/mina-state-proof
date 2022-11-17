import random
import sys
import requests
import logging
import os
import argparse

secret = open(os.path.dirname(os.path.abspath(__file__)) + "/.secret", "r").read()
user = open(os.path.dirname(os.path.abspath(__file__)) + "/.user", "r").read()


def push(data=None):
    if data is None:
        bid_id = sys.argv[1]
        data = {"bid_id": bid_id, "proof": open(sys.argv[2]).read()}

    url = 'http://try.dbms.nil.foundation/market/proof'
    res = requests.post(url=url, json=data, auth=(user, secret))
    if res.status_code != 200:
        logging.error(f"Error: {res.status_code} {res.reason}")
        return
    else:
        logging.info(f"Pushed proof:\t {res.json()}")
        return res.json()

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(message)s')
    parser = argparse.ArgumentParser()
    parser.add_argument('--id', help="Bid's id", default="1")
    parser.add_argument('--proof', help="Path to proof file", default="proof.json")
    args = parser.parse_args()
    data = {"bid_id": args.id, "proof": open(args.proof).read()}
    push(data)
        