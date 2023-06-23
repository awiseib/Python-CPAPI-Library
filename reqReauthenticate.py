import requests
import json
import urllib3
import time

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# reauthenticate
def reauthenticate():
    requests.post(
    url ="https://localhost:5000/v1/api/iserver/reauthenticate", 
    verify=False,
    json={}
    )
    

# Status
def authStatus():
    auth = "false"
    while auth=="false":
        status = requests.get(
        url ="https://localhost:5000/v1/api/iserver/auth/status", 
        verify=False,
        )
        result = json.loads(status.text)["authenticated"]
        if result == True:
            auth=True
        time.sleep(3)
    print("You are authenticated.")

def fullReauth():
    reauthenticate()
    authStatus()

if __name__ == "__main__":
    fullReauth()