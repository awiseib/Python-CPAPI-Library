import requests
import json

# Disable SSL Warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# reauthenticate
def contractSearch():
    base_url = "https://localhost:5000/v1/api/"
    endpoint = "iserver/secdef/search"

    json_body = {"symbol" : "ES", "secType": "STK", "name": False}

    contract_req = requests.post(url=base_url+endpoint, verify=False, json=json_body)

    contract_json = json.dumps(contract_req.json(), indent=2)
    print(contract_json)

if __name__ == "__main__":
    contractSearch()