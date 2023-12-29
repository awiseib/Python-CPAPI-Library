import requests
import json

# Disable SSL Warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def contractSearch():
    base_url = "https://localhost:5000/v1/api/"
    endpoint = "iserver/secdef/search"

    conid = "symbol=RELIANCE"

    params = "&".join([conid])
    request_url = "".join([base_url, endpoint, "?", params])

    search_req = requests.get(url=request_url, verify=False)

    print(search_req.status_code)
    try:
        search_json = json.dumps(search_req.json(), indent=2)
        print(search_json)
    except:
        pass


def contractStrikes():
    base_url = "https://localhost:5000/v1/api/"
    endpoint = "iserver/secdef/strikes"

    conid = "conid=44652000"
    secType = "secType=OPT"
    month = "month=JAN24"
    exchange = "exchange=NSE"

    params = "&".join([conid, secType, month, exchange])
    request_url = "".join([base_url, endpoint, "?", params])

    strikes_req = requests.get(url=request_url, verify=False)

    print(strikes_req.status_code)

    try:
        strikes_json = json.dumps(strikes_req.json(), indent=2)
        print(strikes_json)
    except:
        pass

if __name__ == "__main__":
    contractSearch()
    contractStrikes()