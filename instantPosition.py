# Library Imports
import requests
import time
import urllib3
import json

# Ignore insecure error messages
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Customer wants to receive a list of positions as soon as possible for the order fill

def main():
    baseUrl = "https://localhost:5000/v1/api"
    accountId = "DU257590"
  
    # order_url = f"{baseUrl}/iserver/account/orders?accountId={accountId}"
    # postResponse = requests.get(url = order_url, verify=False)
    # time.sleep(1)
    # postResponse = requests.get(url = order_url, verify=False)
    # response = json.dumps(postResponse.json(), indent=2)
    # print(response)

    
    order_url = f"{baseUrl}/iserver/account/{accountId}/orders"
    source_code = {
        "orders": [
            {
            "conid": 265598,
            "listingExchange": "SMART",
            "orderType": "LMT",
            "price":196,
            "side": "BUY",
            "tif": "DAY",
            "quantity":3,
            }
        ]
    }
    postResponse = requests.post(url = order_url, verify=False, json=source_code)
    response = json.dumps(postResponse.json(), indent=2)
    print(response)
    
    # # time.sleep(1)
    
    # order_url = f"{baseUrl}/iserver/account/orders?accountId={accountId}"
    # postResponse = requests.get(url = order_url, verify=False)
    # time.sleep(1)
    # postResponse = requests.get(url = order_url, verify=False)
    # response = json.dumps(postResponse.json(), indent=2)
    # print(response)

if __name__ == "__main__":
    main()