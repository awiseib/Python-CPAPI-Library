import requests
import time
import json
import urllib3

# Ignore insecure error messages
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def orderRequest():
  
    base_url = "https://localhost:5000/v1/api/"
    endpoint = "iserver/account/orders?force=true"
    
    order_req = requests.get(url=base_url+endpoint, verify=False)
    order_json = json.dumps(order_req.json(), indent=2)

    print(order_req.status_code)
    print("Force. "+order_json)

if __name__ == "__main__":
    while True:
        orderRequest()
        time.sleep(1)