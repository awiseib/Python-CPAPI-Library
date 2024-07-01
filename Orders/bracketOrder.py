import requests
import json
import urllib3

# Ignore insecure error messages
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def orderRequest():
  
    base_url = "https://localhost:5001/v1/api/"
    endpoint = "iserver/account/DU5240685/orders"
    
    coid = "NSE_3"
    conid = 687901547

    json_body = {
        "orders":[
            {
            "cOID": coid,
            "conid": conid,
            "orderType": "MKT",
            # "price":160.25,
            "side": "BUY",
            "tif": "DAY",
            "quantity": 25,
            },
            {
            "parentId":coid,
            "conid": conid,
            "orderType": "LMT",
            "price":70,
            "side": "SELL",
            "tif": "GTC",
            "quantity": 25
            },
            {
            "parentId":coid,
            "conid": conid,
            "orderType": "TRAIL",
            "trailingType":"amt",
            "trailingAmt": 10,
            "side": "SELL",
            "tif": "DAY",
            "quantity": 25
            }
        ]
    }
    
    order_req = requests.post(url=base_url+endpoint, verify=False, json=json_body)
    if order_req.status_code == 200:
        order_json = json.dumps(order_req.json(), indent=2)
        print(order_req.status_code)
        print(order_json)
    else:
        print(order_req.status_code)

if __name__ == "__main__":
    orderRequest()