import requests
import json
import urllib3

# Ignore insecure error messages
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def acctSum():
  
    base_url = "https://localhost:5000/v1/api/"
    endpoint = "portfolio/DU5240685/summary"
    
    sum_req = requests.get(url=base_url+endpoint, verify=False)
    sum_json = json.dumps(sum_req.json(), indent=2)

    print(sum_req.status_code)
    print(sum_json)

if __name__ == "__main__":
    acctSum()