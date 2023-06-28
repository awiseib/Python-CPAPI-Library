# importing the requests library
import requests

# This disables insecure server warning
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# defining the api-endpoint
API_ENDPOINT = "https://localhost:5000/v1/api/iserver/account/{Enter Your Account ID}/orders"

# your source code here
source_code = {
      "orders": [
        {
            "acctId": "",
            "conid": 265598,
            "cOID": "p3",
            "orderType": "LMT",
            "listingExchange": "SMART",
            "price": 157.11,
            "side": "Buy",
            "referrer": "testOCA",
            "tif": "GTC",
            "quantity": 50
        },
        {
            "acctId": "",
            "conid": 265598,
            "orderType": "STP",
            "listingExchange": "SMART",
            "price": 157.30,
            "side": "Sell",
            "tif": "GTC",
            "quantity": 50,
            "parentId": "p3"
        }
      ]
}

# sending post request and saving response as response object
r = requests.post(url = API_ENDPOINT, verify=False, json=source_code)

# extracting response text
postResponse = r.text
print(f"Response: {postResponse}")

splitResponse = postResponse.split('"')
print(splitResponse[3])
confirmation = {"confirmed":True}

REPLY_URL = "https://localhost:5000/v1/api/iserver/reply/"+splitResponse[3]

reply = requests.post(url = REPLY_URL, verify=False, json=confirmation)
print(reply.text)