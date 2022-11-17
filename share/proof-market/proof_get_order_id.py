import requests
import json
import json
import sys

secret = open(".secret", "r").read()
user = open(".user", "r").read()

if __name__ == "__main__":
    url = 'http://try.dbms.nil.foundation/market/proof/order_id/' + sys.argv[1]
    res = requests.get(url=url, auth=(user, secret))
    print(json.loads(res.json()))
