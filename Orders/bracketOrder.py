import requests
import json
import urllib3

# Ignore insecure error messages
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def orderRequest():
  
    base_url = "https://localhost:5001/v1/api/"
    endpoint = "iserver/account/DU5240685/orders"

    json_body = {
        "orders":[
            {
            "cOID":"AAPL_BKT2",
            "conid": 265598,
            "orderType": "LMT",
            "price":160.25,
            "side": "BUY",
            "tif": "DAY",
            "quantity": 1,
            "outsideRth":1
            },
            {
            "parentId":"AAPL_BKT2",
            "conid": 265598,
            "orderType": "MKT",
            # "price":160,
            "side": "SELL",
            "tif": "DAY",
            "quantity": 1,
            "outsideRth":1
            },
            {
            "parentId":"AAPL_BKT2",
            "conid": 265598,
            "orderType": "STP",
            "price":163,
            "side": "SELL",
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