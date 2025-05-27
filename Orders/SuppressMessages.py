import requests
import json
import urllib3
import time

# Ignore insecure error messages
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def suppressRequest():
    coid_iter = f"{int(time.time())}"
    base_url = "https://localhost:5001/v1/api/"
    endpoint = f"iserver/questions/suppress"

    json_body = {"messageIds":["o10164","o10223","o403","o10331","o2137","o10082","o10332","o10333","o10334","o2136","o10335","o10151","o10288","o10152","o10153","o2165","p12","o354","o383","o451","o10138","o163","o382", "o354"]}
    
    order_req = requests.post(url=base_url+endpoint, verify=False, json=json_body)
    order_json = json.dumps(order_req.json(), indent=2)

    print(order_req.status_code)
    print(order_json)


if __name__ == "__main__":
    suppressRequest()
