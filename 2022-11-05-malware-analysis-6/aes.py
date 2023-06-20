# AES encryption
import argparse
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

def aes_encrypt(data, key):
    k = hashlib.sha256(key).digest()
    iv = 16 * '\x00'
    cipher = AES.new(k, AES.MODE_CBC, iv.encode("UTF-8"))
    ciphertext = cipher.encrypt(pad(data, AES.block_size))
    return ciphertext

if __name__ == "__main__":
    # key for encrypt/decrypt
    my_secret_key = get_random_bytes(16)
    parser = argparse.ArgumentParser()
    parser.add_argument('-f','--file', required = True, help = "target file")
    args = vars(parser.parse_args())
    target_file = args['file']
    with open(target_file, 'rb') as f:
        data = f.read()
        if data:
            # encrypted
            ciphertext = aes_encrypt(data, my_secret_key)
            with open("aes.bin", "wb") as result:
                result.write(ciphertext)
