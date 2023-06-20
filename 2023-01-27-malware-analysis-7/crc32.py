import zlib

# crc32
def crc32(data):
    hash = zlib.crc32(data)
    print ("0x%08x" % hash)
    print (hash)
    return hash

crc32(b"MessageBoxA")
