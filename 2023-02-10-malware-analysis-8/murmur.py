def murmurhash2(key: bytes, seed: int) -> int:
    m = 0x5bd1e995
    r = 24
    h = seed ^ len(key)
    data = bytearray(key) + b'\x00' * (4 - (len(key) & 3))
    data = memoryview(data).cast("I")
    for i in range(len(data) // 4):
        k = data[i]
        k *= m
        k ^= k >> r
        k *= m
        h *= m
        h ^= k
    h ^= h >> 13
    h *= m
    h ^= h >> 15
    return h

h = murmurhash2(b"meow-meow", 0)
print ("%x" % h)
print ("%d" % h)