import requests
import json
import json
import sys
import os

secret = open(os.path.dirname(os.path.realpath(__file__)) + "/.secret", "r").read()
user = open(os.path.dirname(os.path.realpath(__file__)) + "/.user", "r").read()

if __name__ == "__main__":
    url = 'http://try.dbms.nil.foundation/market/proof/id/' + sys.argv[1]
    res = requests.get(url=url, auth=(user, secret))
    res_json = json.loads(res.json())
    proof_data = res_json[0]["proof"]
    if res.status_code == 200:
        if len(sys.argv) == 2:
            print(proof_data)
        else:
            with open(sys.argv[2], 'w') as f:
                f.write(proof_data)
    else:
        print("Error: {}".format(res_json["error"]))