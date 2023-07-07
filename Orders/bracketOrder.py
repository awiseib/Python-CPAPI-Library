import requests
import json
import urllib3

# Ignore insecure error messages
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def orderRequest():
  
    base_url = "https://localhost:5000/v1/api/"
    endpoint = "iserver/account/DU5240685/orders"

    json_body = {
        "orders": [
            {
            "cOID": "AAPL_BRACKET_MMDD",
            "conid": 265598,
            "orderType": "MKT",
            "side": "BUY",
            "tif": "DAY",
            "quantity": 10
            },
            {
            "parentId":"AAPL_BRACKET_MMDD",
            "cOID": "AAPL_BRACKET_MMDD-PT",
            "conid": 265598,
            "orderType": "LMT",
            "price":190,
            "side": "BUY",
            "tif": "DAY",
            "quantity": 10
            },
            {
            "parentId":"AAPL_BRACKET_MMDD",
            "cOID": "AAPL_BRACKET_MMDD-SL",
            "conid": 265598,
            "orderType": "STP",
            "price":185,
            "side": "BUY",
            "tif": "DAY",
            "quantity": 10
            }
        ]
    }
    
    order_req = requests.post(url=base_url+endpoint, verify=False, json=json_body)
    order_json = json.dumps(order_req.json(), indent=2)

    print(order_req.status_code)
    print(order_json)

if __name__ == "__main__":
    orderRequest()