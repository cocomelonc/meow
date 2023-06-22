import argparse
import json
import requests
import urllib.parse

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    PURPLE = '\033[95m'
    ENDC = '\033[0m'

# your binaryedge.io API key
BE_API_KEY = '6ec989f3-b13e-4ae7-9836-4294fbdec957'

def binary_edge_request(query, page):
    headers = {'X-Key' : BE_API_KEY}
    url = 'https://api.binaryedge.io/v2/query/search?query=' + query + '&page=' + str(page)
    req = requests.get(url, headers=headers)
    req_json = json.loads(req.content)
    try:
        if req_json.get("status"):
            print (Colors.YELLOW + req_json.get("status") + ' ' + req_json.get("message") + Colors.ENDC)
        else:
            print (Colors.GREEN + "total results: " + str(req_json.get('total')) + Colors.ENDC)
    except Exception as e:
        print (Colors.RED + f"error {e} :(" + bcolors.ENDC)
        sys.exit()
    return req_json.get("events")

def run(query):
    elastic_q = f'"elasticsearch" {query}'.strip()
    elastic_q = urllib.parse.quote(elastic_q)
    elastic_q = f'type:{elastic_q}'
    print (Colors.YELLOW + f'{elastic_q}....' + Colors.ENDC)
    for page in range(1, 2):
        results = binary_edge_request(elastic_q, page)
        if results:
            for service in results:
                print(Colors.BLUE + f"http://{service['target']['ip']}:{service['target']['port']}/_cat/indices" + Colors.ENDC)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='binary edge search')
    parser.add_argument('-q', '--query', required=True, help='binary edge search filter')
    parser.add_argument('-f', '--from', required = False, help = "start page", default = 1)
    parser.add_argument('-t', '--to', required = False, help = "finish page", default = 2)
    args = parser.parse_args()
    query = args.query
    run(query)