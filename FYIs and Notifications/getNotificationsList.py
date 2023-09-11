import requests
import json

# Disable SSL Warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def marketSnapshot():
    base_url = "https://localhost:5000/v1/api/"
    endpoint = "fyi/notifications"

    max_param = "max=10"
    include_param ="include=" # Include what value?
    exclude_param ="exclude=" # Exclude what value?

    params = "&".join([max_param, include_param])
    request_url = "".join([base_url, endpoint, "?", params])

    md_req = requests.get(url=request_url, verify=False)
    md_json = json.dumps(md_req.json(), indent=2)

    print(md_req)
    print(md_json)

if __name__ == "__main__":
    marketSnapshot()