import os
import sys
import time
import json
import requests
import argparse

# for terminal colors
class Colors:
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    PURPLE = '\033[95m'
    ENDC = '\033[0m'

# Malshare API URL
MS_API_URL = "https://malshare.com/api.php"

class MS:
    def __init__(self, api_key):
        self.api_key = api_key

    def upload(self, file_path):
        print (Colors.YELLOW + "upload file " + file_path + "..." + Colors.ENDC)
        try:
            with open(file_path, 'rb') as fp:
                files = {'upload': fp}
                r = requests.post(MS_API_URL, files = files, 
                data = {'api_key': self.api_key, 'action': 'upload'})
                if 'Success' in r.text:
                    print (Colors.GREEN + "successfully update sample :)" + Colors.ENDC)
                    return r.text.split(' - ')[1]
                else:
                    return False
        except Exception as e:
            print(Colors.RED + 'Failed: ' + str(e) + Colors.ENDC)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-m','--mal', required = True, help = "PE file path for scanning")
    args = vars(parser.parse_args())
    ms = MS("your malshare API key")
    print (ms.upload(args["mal"]))
