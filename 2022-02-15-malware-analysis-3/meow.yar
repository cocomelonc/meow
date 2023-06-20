rule meow {
  meta:
    author = "cocomelonc"
    category = "test"
    description = "test rule for meow-meow messagebox"

  strings:
    $a = "meow"
    $b = {4D 65 6F 77 2D 6D 65 6F 77}
    $mz = {4D 5A}

  condition:
    ($mz at 0x00) and ($a or $b)
}
