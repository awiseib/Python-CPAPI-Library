import requests
import urllib3
import prettyPrint
import json
# Ignore insecure error messages
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def main():
  
    order_url = "https://localhost:5000/v1/api/iserver/account/orders"
    postResponse = requests.get(url = order_url, verify=False)
    prettyPrint.pprint(postResponse)
    # print(type(json.loads(postResponse.text)))

if __name__ == "__main__":
    main()