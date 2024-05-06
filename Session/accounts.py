import requests
import json

# Disable SSL Warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def reqAccounts():
    base_url = "https://localhost:5000/v1/api/"
    endpoint = "iserver/accounts"

    accts_req = requests.get(url=base_url+endpoint, verify=False)
    accts_json = json.dumps(accts_req.json(), indent=2)

    print(accts_req)
    print(accts_json)

if __name__ == "__main__":
    reqAccounts()