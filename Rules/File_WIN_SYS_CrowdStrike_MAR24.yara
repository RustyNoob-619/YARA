
rule File_WIN_SYS_CrowdStrike_MAR24
{
  meta:
    author = "RustyNoob619"
    description = "Detects the CrowdStrike system files which is crashing on Windows Systems"
    credits = "@Now_on_VT for sharing the file samples"
    reference = "https://x.com/Now_on_VT/status/1814249297430348090"
    
  strings:
    $header = {aa aa aa aa 01 00 23 01}
    $nop = {5c 4e}
    $str1 = "AbCDEfghIjklMNoPqrstuV"
    $str2 = "ABCDEfGhIJKLMNOPqRSTUVW"
    $str3 = "000E0A000E0GHijklMNOPqRSTUVwX"
    
  condition:
    $header
    and #nop > 50
    and all of ($str*)
    and filesize < 50KB
}
