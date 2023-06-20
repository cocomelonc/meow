import argparse

output = ""
plaintext = open("./meow.bin", "rb").read()
for i in range(len(plaintext)):
    current = plaintext[i]
    ordd = lambda x: x if isinstance(x, int) else ord(x)
    output += chr(ordd(current))
cbytes = '{ 0x' + ', 0x'.join(hex(ord(x))[2:] for x in output) + ' };'
print (cbytes)