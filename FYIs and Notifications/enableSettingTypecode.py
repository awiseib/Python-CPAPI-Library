import requests
import json

# Disable SSL Warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def enableTypecode():
    base_url = "https://localhost:5000/v1/api/"
    endpoint = "fyi/settings/SM"
    """
    ba = borrow availability
    ca = comparative algo
    da = dividends advisory
    ea = upcoming earnings
    mf = mutual fund advisory
    oe = option expiration
    pr = portfolio builder rebalance
    se = suspend order on economic event
    sg = short term gain turning long term
    sm = system messages
    t2 = assignment realizing long-term gains
    to = takeover
    ua = user alert
    m8 = M871 trades
    ps = platform suggestions
    dl = unexercised option loss prevention reminder
    pt = position transfer
    cb = missing cost basis
    ms = milestones
    td = MiFID II 10% deprecation notice
    st = save taxes
    ti = trading idea
    ct = cash transfer
    """

    json_body = {
        "enabled": False
    }
    
    typecode_req = requests.post(url=base_url+endpoint, verify=False, json=json_body)
    print(typecode_req)

    if typecode_req.status_code == 200:
        typecode_json = json.dumps(typecode_req.json(), indent=2)
        print(typecode_json)


if __name__ == "__main__":
    enableTypecode()