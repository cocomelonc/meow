rule murmurhash2_rule {
  meta:
    author = "cocomelonc"
    description = "example rule using MurmurHash2A with constant 0x5bd1e995"
  strings:
    $hash = { 95 e9 d1 5b }
  condition:
    $hash
}
