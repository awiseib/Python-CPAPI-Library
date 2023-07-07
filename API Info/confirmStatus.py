import requests

# Disable SSL Warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# reauthenticate
def confirmStatus():
    base_url = "https://localhost:5000/v1/api/"
    endpoint = "iserver/auth/status"
    
    auth_req = requests.get(url=base_url+endpoint,verify=False)
    print(auth_req)
    print(auth_req.text)

if __name__ == "__main__":
    confirmStatus()