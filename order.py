import requests
import urllib3
from prettyPrint import pprint

# Ignore insecure error messages
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def main():
  
    order_url = "".join(["https://localhost:5000/v1/api/iserver/account/DU5240685/orders"])
    source_code = {
        "orders": [
            {
            "conid": 8312,
            "orderType": "MKT",
            "side": "BUY",
            "tif": "DAY",
            "quantity":10,
            }
        ]
    }
    postResponse = requests.post(url = order_url, verify=False, json=source_code, headers={"Content-Type":"application/json"})
    print(postResponse)
    print(postResponse.text)

if __name__ == "__main__":
    main()