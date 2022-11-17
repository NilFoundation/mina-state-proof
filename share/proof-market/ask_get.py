import requests
import sys
import os

secret = open(os.path.dirname(os.path.abspath(__file__)) + "/.secret", "r").read()
user = open(os.path.dirname(os.path.abspath(__file__)) + "/.user", "r").read()

if __name__ == "__main__":
    url = 'http://try.dbms.nil.foundation/market/ask/id/' + sys.argv[1]
    res = requests.get(url=url, auth=(user, secret))
    print(res.json())
