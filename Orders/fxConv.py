import requests
import json
import urllib3
import time

# Ignore insecure error messages
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

ACCT_ID = "DU5240685"


def orderRequest():
    coid_iter = f"{int(time.time())}"
    base_url = "https://localhost:5000/v1/api/"
    endpoint = f"iserver/account/{ACCT_ID}/orders"

    json_body =   {
        "orders": [
            {
            "conid": 12087797,
            "fxQty": 25000,
            "isCcyConv": True,
            "orderType": "LMT",
            "price":1.1234,
            "side": "BUY",
            "tif": "DAY"
            }
        ]
    }
    
    
    order_req = requests.post(url=base_url+endpoint, verify=False, json=json_body)
    order_json = json.dumps(order_req.json(), indent=2)

    print(order_req.status_code)
    print(order_json)

if __name__ == "__main__":
    orderRequest()