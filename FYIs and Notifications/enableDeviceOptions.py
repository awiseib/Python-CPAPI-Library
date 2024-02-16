import requests
import json

# Disable SSL Warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def marketSnapshot():
    base_url = "https://localhost:5000/v1/api/"
    endpoint = "fyi/deliveryoptions/device"

    json_body = {
        "devicename": "string",
        "deviceId": "string",
        "uiName": "string",
        "enabled": True
    }
    
    typecode_req = requests.post(url=base_url+endpoint, verify=False, json=json_body)
    print(typecode_req)

    if typecode_req.status_code == 200:
        typecode_json = json.dumps(typecode_req.json(), indent=2)
        print(typecode_json)

if __name__ == "__main__":
    marketSnapshot()