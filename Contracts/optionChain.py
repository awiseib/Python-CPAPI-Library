import requests
import json

# Disable SSL Warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
BASE_URL = "https://localhost:5001/v1/api"

def contractSearch():
    endpoint = "/iserver/secdef/search"

    conid = "symbol=CL"

    params = "&".join([conid])
    request_url = "".join([BASE_URL, endpoint, "?", params])

    search_req = requests.get(url=request_url, verify=False)

    print(search_req.status_code)
    try:
        search_json = json.dumps(search_req.json(), indent=2)
        print(search_json)
    except:
        pass


def contractStrikes():
    endpoint = "/iserver/secdef/strikes"

    conid = "conid=17340715"
    secType = "secType=FOP"
    month = "month=MAR24"
    exchange = "exchange=NYMEX"

    params = "&".join([conid, secType, month, exchange])
    request_url = "".join([BASE_URL, endpoint, "?", params])

    strikes_req = requests.get(url=request_url, verify=False)

    print(strikes_req.status_code)

    try:
        strikes_json = json.dumps(strikes_req.json(), indent=2)
        print(strikes_json)
    except:
        pass

if __name__ == "__main__":
    # contractSearch()
    contractStrikes()