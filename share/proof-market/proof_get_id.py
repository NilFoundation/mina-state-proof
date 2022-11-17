import requests
import sys
import os
import logging

secret = open(os.path.dirname(os.path.abspath(__file__)) + "/.secret", "r").read()
user = open(os.path.dirname(os.path.abspath(__file__)) + "/.user", "r").read()

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(message)s')
    url = 'http://try.dbms.nil.foundation/market/proof/id/' + sys.argv[1]
    res = requests.get(url=url, auth=(user, secret))
    if res.status_code != 200:
        logging.error(f"Error: {res.status_code} {res.reason}")
        exit(1)
    else:
        res_json = res.json()
        proof_data = res_json["proof"]
        if len(sys.argv) > 2:
            with open(sys.argv[2], 'w') as f:
                f.write(proof_data)
        logging.info(f"Proof:\t\t {res_json}")
        
