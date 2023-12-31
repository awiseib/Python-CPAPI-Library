import requests
import json
import urllib3

# Ignore insecure error messages
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def orderModify():
  
    base_url = "https://localhost:5000/v1/api/"
    endpoint = "iserver/account/DU5240685/order/"
    order_id = "366866174"

    json_body= {
        "conid": 568549928  ,
        "orderType":"STP",
        "price": 15582,
        "side":"BUY",
        "tif":"DAY",
        "quantity":1
    }

    modify_url = "".join([base_url, endpoint, order_id])
    
    order_req = requests.post(url=modify_url, verify=False, json=json_body)
    order_json = json.dumps(order_req.json(), indent=2)

    print(order_req.status_code)
    print(order_json)

if __name__ == "__main__":
    orderModify()