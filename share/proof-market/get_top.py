import requests
import sys
import os
import logging

secret = open(os.path.dirname(os.path.abspath(__file__)) + "/.secret", "r").read()
user = open(os.path.dirname(os.path.abspath(__file__)) + "/.user", "r").read()

def get():
    url = 'http://try.dbms.nil.foundation/market/top'
    try:
        res = requests.get(url=url, auth=(user, secret))
    except requests.exceptions.ConnectionError:
        res.status_code = "Connection refused"
    if res.status_code == 200:
        return res.json()
    return {'bid': None, 'ask': None}

def get_costs():
    top = get()
    # logging.info(top)
    if top['bid'] and top['ask']:
        top = {'ask': top['ask']['cost'], 'bid': top['bid']['cost']}
        logging.info(f"Top:\t\t {top}")
        return top
    else:
        return {}


if __name__ == "__main__":
    print(get())
