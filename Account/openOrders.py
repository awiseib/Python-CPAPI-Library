import requests
import json
import urllib3

# Ignore insecure error messages
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def orderRequest():
  
    base_url = "https://localhost:5001/v1/api/"
    endpoint = "iserver/account/orders"
    
    order_req = requests.get(url=base_url+endpoint, verify=False)
    order_json = json.dumps(order_req.json(), indent=2)

    print(order_req.status_code)
    print(order_json)

if __name__ == "__main__":
    orderRequest()