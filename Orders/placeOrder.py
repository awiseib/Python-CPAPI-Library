import requests
import json
import urllib3

# Ignore insecure error messages
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def orderRequest():
  
    base_url = "https://localhost:5000/v1/api/"
    endpoint = "iserver/account/DU5240685/orders"

    json_body = {
        "orders": [{
            "conid": 497222760,
            "orderType": "STP LMT",
            "price":4450,
            "auxPrice":4460,
            "side": "BUY",
            "tif": "DAY",
            "quantity": 10
        }]
    }
    
    
    order_req = requests.post(url=base_url+endpoint, verify=False, json=json_body)
    order_json = json.dumps(order_req.json(), indent=2)

    print(order_req.status_code)
    print(order_json)
    try:
        if order_req.json()[0]["id"]:
            print(order_req.json()[0]["id"])
        else:
            print(order_req.json()[0]["id"])
    except:
        pass

if __name__ == "__main__":
    orderRequest()