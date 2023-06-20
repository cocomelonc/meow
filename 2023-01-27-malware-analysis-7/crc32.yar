rule crc32_hash
{
  meta:
    author = "cocomelonc"
    description = "crc32 constants"
  strings:
    $c = { 2083B8ED }
  condition:
    $c
}
