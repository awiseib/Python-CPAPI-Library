import requests
import json

# Disable SSL Warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def marketSnapshot():
    base_url = "https://localhost:5000/v1/api/"
    endpoint = "fyi/disclaimer/"
    
    typecode = "SM"

    request_url = "".join([base_url, endpoint, typecode])

    md_req = requests.put(url=request_url, verify=False)
    md_json = json.dumps(md_req.json(), indent=2)

    print(md_req)
    print(md_json)

if __name__ == "__main__":
    marketSnapshot()