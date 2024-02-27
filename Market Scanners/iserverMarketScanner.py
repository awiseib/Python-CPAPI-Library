# Library Imports
import requests
import urllib3
import json

# Ignore insecure error messages
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def reqIserverScanner():
    base_url = "https://localhost:5000/v1/api/"
    endpoint = "iserver/scanner/run"

    scan_body = {
        "instrument": "STOCK.HK",
        "location": "STK.HK.NSE",
        "type": "TOP_PERC_GAIN",
        "filter": [
            {
                "code":"priceAbove",
                "value":101
            },
            {
                "code":"priceBelow",
                "value":110
            }
        ]
    }

    scan_req = requests.post(url=base_url+endpoint, verify=False, json=scan_body)
    scan_json = json.dumps(scan_req.json(), indent=2)

    print(scan_req.status_code)
    print(scan_json)
    
if __name__ == "__main__":
    reqIserverScanner()