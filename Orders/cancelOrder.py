import requests
import json
import urllib3

# Ignore insecure error messages
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def orderCancel():
  
    base_url = "https://localhost:5000/v1/api/"
    endpoint = "iserver/account/DU5240685/order/"
    order_id = "949820376"

    cancel_url = "".join([base_url, endpoint, order_id])
    
    cancel_req = requests.delete(url=cancel_url, verify=False)
    cancel_json = json.dumps(cancel_req.json(), indent=2)

    print(cancel_req.status_code)
    print(cancel_json)

if __name__ == "__main__":
    orderCancel()