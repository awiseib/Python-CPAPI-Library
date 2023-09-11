# Library Imports
import requests
import time
import urllib3
import json

# Ignore insecure error messages
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def hmds_data():
    params_url = "https://localhost:5000/v1/api/hmds/history?conid=265598&period=1d&bar=1hour&outsideRth=false&barType=last"
    params_req = requests.get(url=params_url, verify=False)
    
    params_json = json.dumps(params_req.json(), indent=2)
    
    print(params_json)
    
if __name__ == "__main__":
    hmds_data()