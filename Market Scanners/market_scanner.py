# Library Imports
import requests
import time
import urllib3
import json

# Ignore insecure error messages
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def reqIserverScanner():
    scan_url = "https://localhost:5000/v1/api/iserver/scanner/run"
    scan_body = {
        "instrument": "STK",
        "locations": "STK.US.MAJOR",
        "type": "TOP_PERC_GAIN",
        "filter":[
            {
                "code":"priceAbove",
                "value": 100, 
            },
            {
                "code":"priceBelow",
                "value": 110, 
            }
        ]
    }
    scan_req = requests.post(url=scan_url, verify=False, json=scan_body)
    
    # print(scan_req)
    # print(scan_req.text)
    results = json.loads(scan_req.text)["contracts"]
    for i in results:
        print(i)

    
if __name__ == "__main__":
    reqIserverScanner()