import argparse

## XOR function to encrypt data
def xor(data, key):
    key = str(key)
    l = len(key)
    output_str = ""

    for i in range(len(data)):
        current = data[i]
        current_key = key[i % len(key)]
        ordd = lambda x: x if isinstance(x, int) else ord(x)
        output_str += chr(ordd(current) ^ ord(current_key))
    return output_str

## encrypting
def xor_encrypt(data, key):
    ciphertext = xor(data, key)
    ciphertext_str = '{ 0x' + ', 0x'.join(hex(ord(x))[2:] for x in ciphertext) + ' };'
    print (ciphertext_str)
    return ciphertext

if __name__ == "__main__":
    # key for encrypt/decrypt
    my_secret_key = "mysupersecretkey"
    parser = argparse.ArgumentParser()
    parser.add_argument('-f','--file', required = True, help = "target file")
    args = vars(parser.parse_args())
    target_file = args['file']
    with open(target_file, 'rb') as f:
        data = f.read()
        if data:
            # encrypted
            ciphertext = xor_encrypt(data, my_secret_key)
            with open("xor.bin", "wb") as result:
                result.write(ciphertext.encode())
