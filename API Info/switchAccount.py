import requests
import json

# Disable SSL Warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def switchAccount():
    base_url = "https://localhost:5000/v1/api/"
    endpoint = "iserver/account"

    acct_body = {
        "acctId":"video_group"
    }

    md_req = requests.post(url=base_url+endpoint, verify=False, json=acct_body)
    md_json = json.dumps(md_req.json(), indent=2)

    print(md_req)
    print(md_json)

if __name__ == "__main__":
    switchAccount()