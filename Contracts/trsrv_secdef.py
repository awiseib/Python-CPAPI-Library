import requests
import json

# Disable SSL Warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# reauthenticate
def contractSearch():
    base_url = "https://localhost:5000/v1/api/"
    endpoint = "trsrv/secdef"

    json_body = {"conids" : [75961314]}

    contract_req = requests.post(url=base_url+endpoint, verify=False, json=json_body)

    contract_json = json.dumps(contract_req.json(), indent=2)
    print(contract_json)

if __name__ == "__main__":
    contractSearch()