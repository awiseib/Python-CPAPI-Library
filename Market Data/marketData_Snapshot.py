import requests
import json

# Disable SSL Warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def marketSnapshot():
    base_url = "https://localhost:5000/v1/api/"
    endpoint = "iserver/marketdata/snapshot"

    conid="conids=265598"
    fields="fields=31,55,84,86"


    params = "&".join([conid, fields])
    request_url = "".join([base_url, endpoint, "?", params])

    md_req = requests.get(url=request_url, verify=False)
    md_json = json.dumps(md_req.json(), indent=2)

    print(md_req)
    print(md_json)

if __name__ == "__main__":
    marketSnapshot()