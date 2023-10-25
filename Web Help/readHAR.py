import json
from haralyzer import HarParser
    
   
def main():
    HAR = "D:\\Downloads\\503_5.har"
    newFile = "D:\\Downloads\\503_5-cleanHar.har"

    with open(file=HAR, mode='r', encoding="utf-8-sig") as f:
        har_parser = HarParser(json.loads(f.read()))

    data = har_parser.har_data
    print(data["entries"][0].keys())
    cleanHar = open(newFile, "w")
    for i in range(len(data["entries"])):
        request_root = data["entries"][i]["request"]
        cleanHar.write('\n-----------REQUEST-----------\n')
        cleanHar.write(f"Method: {request_root['method']}\n")
        cleanHar.write(f"URL: {request_root['url']}\n")
        cleanHar.write(f"Query: {request_root['queryString']}\n")
        cleanHar.write('\n'.join(f'{i}' for i in request_root['headers']))
        cleanHar.write("\n")
        try:
            cleanHar.write(request_root['postData']['text'])
            cleanHar.write("\n")
        except:
            pass
        
        response_root = data["entries"][i]["response"]
        cleanHar.write('\n-----------RESPONSE-----------\n')
        cleanHar.write(f"Status: {response_root['status']}\n")
        cleanHar.write(f"Status Text: {response_root['statusText']}\n")
    cleanHar.close()
        

if __name__ == "__main__":
    main()