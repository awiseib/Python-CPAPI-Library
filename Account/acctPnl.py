import requests
import json
import urllib3

# Ignore insecure error messages
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def acctPos():
  
    base_url = "https://localhost:5000/v1/api/"
    endpoint = "iserver/account/pnl/partitioned"
    
    pos_req = requests.get(url=base_url+endpoint, verify=False)
    pos_json = json.dumps(pos_req.json(), indent=2)

    print(pos_req.status_code)
    print(pos_json)

if __name__ == "__main__":
    acctPos()