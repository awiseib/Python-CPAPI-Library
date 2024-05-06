import requests

# Disable SSL Warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# reauthenticate
def confirmStatus():
    base_url = "https://localhost:5001/v1/api/"
    endpoint = "iserver/auth/status"
    
    auth_req = requests.post(url=base_url+endpoint,
                             verify=False,
                             json={"publish":True, "compete": True})
    print(auth_req)
    print(auth_req.text)

if __name__ == "__main__":
    confirmStatus()