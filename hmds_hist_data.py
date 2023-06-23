# Library Imports
import requests
import time
import urllib3
import json
from prettyPrint import pprint

# Ignore insecure error messages
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def hmds_data():
    params_url = "https://localhost:5000/v1/api/hmds/history?conid=76792991&period=1d&bar=1hour&outsideRth=false&barType=last"
    params_req = requests.get(url=params_url, verify=False)
    
    # You can import os then run "os.getcwd()" to see pythons default dir. 
    return params_req

def main():
    pprint(hmds_data())
    
if __name__ == "__main__":
    main()