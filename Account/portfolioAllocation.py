# Library Imports
import requests
import time
import urllib3
import json

# Ignore insecure error messages
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def reqIserverScanner():
    scan_url = "https://localhost:5000/v1/api/portfolio/DU74649/allocation?lucastest1"
    scan_req = requests.get(url=scan_url, verify=False)
    
    print(scan_req)
    # print(scan_req.text)
    results = json.loads(scan_req.text)
    for i in results.keys():
        print(i)
        print(results[i])
        print()

    
if __name__ == "__main__":
    reqIserverScanner()