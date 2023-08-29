import requests
import json
import threading
from time import sleep

# Disable SSL Warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def getUnderConid(underlyingSymbol, exchange="SMART"):
    base_url = "https://localhost:5000/v1/api/"
    endpoint = "iserver/secdef/search"
    json_body = {"symbol" : underlyingSymbol,
                 "exchange": exchange}
    contract_req = requests.post(url=base_url+endpoint, verify=False, json=json_body)
    print("/iserver/secdef/search: ", contract_req.status_code)

    if contract_req.status_code != 200:
        exit()

    underConid = contract_req.json()[0]["conid"]
    frontMonth = contract_req.json()[0]["sections"][1]["months"].split(';')[0]

    return underConid,frontMonth

def getStrikes(underConid,frontMonth, exchange="SMART"):
    
    base_url = "https://localhost:5000/v1/api/"
    endpoint = "iserver/secdef/strikes"
    conid = "conid="+underConid
    secType = "secType=OPT"
    month = "month="+frontMonth

    params = "&".join([conid, secType, month, exchange])
    request_url = "".join([base_url, endpoint, "?", params])

    strikes_req = requests.get(url=request_url, verify=False)
    print("Strikes: ", strikes_req.status_code)
    calls = strikes_req.json()["call"]
    
    return calls

# This seems unecessary when we can just split the list
def getTheMoney(underConid):
    base_url = "https://localhost:5000/v1/api/"
    endpoint = "iserver/marketdata/snapshot"

    conid="conids="+underConid
    fields="fields=31"

    params = "&".join([conid, fields])
    request_url = "".join([base_url, endpoint, "?", params])

    preflight = requests.get(url=request_url, verify=False)
    md_req = requests.get(url=request_url, verify=False)

    if md_req.status_code != 200:
        print(md_req.status_code)
        print(md_req.text)
    else:
        curPrice = md_req.json()[0]["31"]
        return float(curPrice)

def itmStrikes(right, curPrice):
    midpoint = len(right)//2

    lowCut = right[:midpoint]
    for n,i in enumerate(lowCut):
        if i%1 != 0:
            lowCut.pop(n)
    if len(lowCut) > 4:
        lowCut = lowCut[-6:-1]

    highCut = right[midpoint:]
    for n,i in enumerate(highCut):
        if i%1 != 0:
            highCut.pop(n)
    if len(highCut) > 4:
        highCut = highCut[0:5]
        
    return lowCut+highCut

def optConids(underConid, frontMonth, strikes, exchangeVal="SMART"):
    base_url = "https://localhost:5000/v1/api/"
    endpoint = "iserver/secdef/info"

    conidList = []

    for strikeVal in strikes:
        conid = f"conid={underConid}"
        secType = "secType=OPT"
        month = f"month={frontMonth}"
        exchange = f"exchange={exchangeVal}"
        strike = f"strike={strikeVal}"
        right = "right=C"

        params = "&".join([conid, secType, month, exchange, strike, right])
        request_url = "".join([base_url, endpoint, "?", params])
        try:
            contract_req = requests.get(url=request_url, verify=False)
            conidList.append(contract_req.json()[0]["conid"])
        except:
            print(request_url)
            print(contract_req.status_code)
            print(contract_req.text)
        # sleep(5)
    return conidList

def historicalData(conidVal):
    base_url = "https://localhost:5000/v1/api/"
    endpoint = "iserver/marketdata/history"

    conid=f"conid={conidVal}"
    period="period=1d"
    bar="bar=1h"
    startTime="startTime=20230829-16:00:00"
    outsideRth="outsideRth=false"
    barType="barType=AllLast"

    params = "&".join([conid, period, bar, startTime, outsideRth, barType])
    request_url = "".join([base_url, endpoint, "?", params])

    hd_req = requests.get(url=request_url, verify=False)
    if hd_req.status_code == 500:
        print(hd_req.status_code)
        print(hd_req.text)
    else:
        hd_json = json.dumps(hd_req.json(), indent=2)
        print(hd_req.json()["text"])

def main():
    # First get the underlying's details
    underConid,frontMonth=getUnderConid("SPX", exchange="CBOE")
    # Get all strikes for our underlying
    calls = getStrikes(underConid,frontMonth)

    # Confirm the current price
    curPrice = getTheMoney(underConid)

    # Then grab the 10 strikes on both sides of the money
    strikes = itmStrikes(calls, curPrice)

    # Get the conids for said contracts
    conidList = optConids(underConid, frontMonth, strikes)
    print(conidList)
    
    # Send out historical data requests. 
    for strike in conidList:
        historicalData(strike)


if __name__ == "__main__":
    main()
    # for i in [265598, # Apple Inc. 
    #           8314,     # IBM
    #           8894,     # Coca-Cola
    #           76792991, # Tesla
    #           9599491,  # Ford
    #           11017,    # Pepsi
    #           274105    # Starbucks
    #           ]:
    #     threading.Thread(target=historicalData, args=(i,)).start()