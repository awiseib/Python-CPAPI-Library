import requests
import json
import urllib3

# Ignore insecure error messages
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

'''
This program is an extension of the information posted to https://www.interactivebrokers.com/campus/ibkr-api-page/cpapi-v1/#combo-orders

Be sure to update the base_url and accountId variables to reflect your implementation.
'''
accountId = "DU5240685"
base_url = "https://localhost:5001/v1/api/"

def orderRequest():

    endpoint = f"iserver/account/{accountId}/orders"

    json_body = {
        "orders": [
            {
                "conidex":"28812380;;;682672008/1,682672073/-1,682674556/-1,682674846/1", # AAPL Oct 18th Options: BUY 230 C, SELL 235 C, SELL 195 P, BUY 220 P
                "orderType": "LMT",
                "price": 4.13, # The limit is the total of our combo legs
                "side": "BUY",
                "tif": "DAY",
                "quantity": 3 # This will 
            }
        ]
    }
    
    order_req = requests.post(url=base_url+endpoint, verify=False, json=json_body)
    order_json = json.dumps(order_req.json(), indent=2)
    
    print(order_req.status_code)
    print(order_json)

if __name__ == "__main__":
    orderRequest()