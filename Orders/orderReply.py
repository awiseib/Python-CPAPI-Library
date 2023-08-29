import requests
import json
import urllib3

# Ignore insecure error messages
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def orderReply():
  
    base_url = "https://localhost:5000/v1/api/"
    endpoint = "iserver/reply/"
    replyId = "afd74221-a19c-4fb3-8a0c-02669e41cd6d"

    reply_url = "".join([base_url, endpoint, replyId])

    json_body = {"confirmed":True}


    reply_req = requests.post(url=reply_url, verify=False, json=json_body)
    reply_json = json.dumps(reply_req.json(), indent=2)

    print(reply_req.status_code)
    print(reply_json)

if __name__ == "__main__":
    orderReply()