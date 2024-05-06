import requests
import urllib3

import csv

# Ignore insecure error messages
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def secdefSearch(symbol, listingExchange):

  url = f'https://localhost:5001/v1/api/iserver/secdef/search?symbol={symbol}'

  search_request = requests.get(url=url, verify=False)
  for contract in search_request.json():
    if contract["description"] == listingExchange:
      underConid = contract["conid"]

      for secType in contract["sections"]:
         if secType["secType"] == "OPT":
            months = secType["months"].split(';')

  return underConid,months

def secdefStrikes(underConid,month):

  snapshot = float(snapshotData(underConid))
  itmStrikes = []

  url = f'https://localhost:5001/v1/api/iserver/secdef/strikes?conid={underConid}&secType=OPT&month={month}'

  strike_request = requests.get(url=url, verify=False)

  strikes = strike_request.json()["put"]
  for strike in strikes:
    if strike>snapshot-10 and strike<snapshot+10:
      itmStrikes.append(strike)
  return itmStrikes

def secdefInfo(conid, month, strike):

  url = f'https://localhost:5001/v1/api/iserver/secdef/info?conid={conid}&month={month}&strike={strike}&secType=OPT&right=P'

  info_request = requests.get(url=url, verify=False)

  contracts = []

  for contract in info_request.json():
    contractDetails = {"conid": contract["conid"], 
                       "symbol": contract["symbol"],
                       "strike": contract["strike"],
                       "maturityDate": contract["maturityDate"]
                      }
    contracts.append(contractDetails)
  return contracts

def snapshotData(underConid):
  url = f'https://localhost:5001/v1/api/iserver/marketdata/snapshot?conids={underConid}&fields=31'
  requests.get(url=url, verify=False)
  snapshot = requests.get(url=url, verify=False)
  return snapshot.json()[0]["31"]

def writeResult(contractDict):
  headers = ["conid", "symbol", "strike", "maturityDate"]
  filePath = "./MayContracts.csv"
  contract_csv_file = open(filePath, 'w', newline='')
  contract_writer = csv.DictWriter(f=contract_csv_file, fieldnames=headers)
  contract_writer.writeheader()
  for strikeGroup in contractDict:
    for contractDetails in contractDict[strikeGroup]:
      contract_writer.writerow(contractDetails)
  contract_csv_file.close()
  print("Job's done.")

if __name__ == "__main__":
  # I'm looking for the U.S. Apple Incorporated company listed on NASDAQ
  underConid,months = secdefSearch("AAPL", "NASDAQ")
  
  # I only want the front month. 
  # Users could always grab all months, or pull out a specific value, but sending the 0 value always gives me the first available contract.
  month = months[0]

  # We'll be calling our Strikes endpoint to pull in the money strike prices rather than all strikes.
  itmStrikes = secdefStrikes(underConid,month)

  # We can then pass those strikes to the /info endpoint, and retrieve all the contract details we need.
  contractDict = {}
  for strike in itmStrikes:
    contractDict[strike] = secdefInfo(underConid,month,strike)

  writeResult(contractDict)