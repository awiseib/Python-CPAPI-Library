# Library Imports
import requests
import time
import urllib3
import json

# Ignore insecure error messages
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def hmds_data():
    params_url = "https://localhost:5001/v1/api/hmds/history"
    params = { "conid": 272093, "period": "4y", "bar": "1min" } 
    params_req = requests.get(url=params_url, params=params, verify=False)
    if params_req.status_code == 200:
        print(params_req.status_code)
        params_json = json.dumps(params_req.json(), indent=2)
        print(params_json)
    else:
        print(params_req.status_code)
        print(params_req.content)
        
    
if __name__ == "__main__":
    hmds_data()