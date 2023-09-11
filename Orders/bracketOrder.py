import requests
import json
import urllib3

# Ignore insecure error messages
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def orderRequest():
  
    base_url = "https://localhost:5000/v1/api/"
    endpoint = "iserver/account/DU5240685/orders"

    json_body = {
        "orders":[
            {
            "cOID":"NQ_STOP_oRTH3",
            "conid": 568549928,
            "orderType": "LMT",
            "price":15584.25,
            "side": "SELL",
            "tif": "DAY",
            "quantity": 1,
            "outsideRth":1
            },
            {
            "parentId":"NQ_STOP_oRTH3",
            "conid": 568549928,
            "orderType": "STP",
            "price":15590,
            "side": "BUY",
            "tif": "DAY",
            "quantity": 1,
            "outsideRth":1
            }
        ]
    }
    
    order_req = requests.post(url=base_url+endpoint, verify=False, json=json_body)
    order_json = json.dumps(order_req.json(), indent=2)

    print(order_req.status_code)
    print(order_json)

if __name__ == "__main__":
    orderRequest()