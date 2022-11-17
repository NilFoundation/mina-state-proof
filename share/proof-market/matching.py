import requests
import json
import sys
import logging
import os

secret = open(os.path.dirname(os.path.abspath(__file__)) + "/.secret", "r").read()
user = open(os.path.dirname(os.path.abspath(__file__)) + "/.user", "r").read()


def match_top():
    url = 'http://try.dbms.nil.foundation/market/match'
    res = requests.get(url=url, auth=(user, secret))
    if res.status_code != 200:
        logging.error(f"Error: {res.status_code} {res.reason}")
        return
    else:
        logging.info(f"Matched:\t {res.json()}")
        return res.json()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(message)s')
    res = match_top()
