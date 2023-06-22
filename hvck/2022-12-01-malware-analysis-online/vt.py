import os
import sys
import time
import json
import requests
import argparse
import hashlib

# for terminal colors
class Colors:
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    PURPLE = '\033[95m'
    ENDC = '\033[0m'

# VirusTotal API key
VT_API_KEY = "your API key"

# VirusTotal API v3 URL
VT_API_URL = "https://www.virustotal.com/api/v3/"

# upload malicious file to VirusTotal and analyse
class VT:
    def __init__(self):
        self.headers = {
            "x-apikey" : VT_API_KEY,
        }

    def upload(self, malware_path):
        print (Colors.BLUE + "upload file: " + malware_path + "..." + Colors.ENDC)
        self.malware_path = malware_path
        upload_url = VT_API_URL + "files"
        files = {"file" : (
            os.path.basename(malware_path),
            open(os.path.abspath(malware_path), "rb"))
        }
        print (Colors.YELLOW + "upload to " + upload_url + Colors.ENDC)
        try:
            res = requests.post(upload_url, headers = self.headers, files = files)
        except:
            print (Colors.RED + "failed to upload PE file, cannot send API req :(" + Colors.ENDC)
            sys.exit()
        else:
            if res.status_code == 200:
                result = res.json()
                self.file_id = result.get("data").get("id")
                print (Colors.YELLOW + self.file_id + Colors.ENDC)
                print (Colors.GREEN + "successfully upload PE file: OK" + Colors.ENDC)
            else:
                print (Colors.RED + "failed to upload PE file :(" + Colors.ENDC)
                print (Colors.RED + "status code: " + str(res.status_code) + Colors.ENDC)
                sys.exit()

    def analyse(self):
        self.results = None
        print (Colors.BLUE + "get info about the results of analysis..." + Colors.ENDC)
        analysis_url = VT_API_URL + "analyses/" + self.file_id
        try:
            res = requests.get(analysis_url, headers = self.headers)
        except:
            print (Colors.RED + "failed to get info, cannot send API req :(" + Colors.ENDC)
            sys.exit()
        else:
            if res.status_code == 200:
                print (res.json())
                self.results = res.json()
            else:
                print (Colors.RED + "failed to get results of analysis :(" + Colors.ENDC)
                print (Colors.RED + "status code: " + str(res.status_code) + Colors.ENDC)
                self.results = None
        return self.results               

    def run(self, malware_path):
        self.upload(malware_path)
        self.analyse()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-m','--mal', required = True, help = "PE file path for scanning")
    args = vars(parser.parse_args())
    vt = VT()
    vt.run(args["mal"])
