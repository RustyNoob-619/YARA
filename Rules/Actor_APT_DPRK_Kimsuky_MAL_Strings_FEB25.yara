rule Actor_APT_DPRK_Kimsuky_MAL_Strings_FEB25
{
  meta:
    author = "RustyNoob619"
    description = "This rule identifies Kimsuky related malware based on observed artifacts"
    credit = "@smica83 for sharing the malware sample"
    source = "https://x.com/smica83/status/1884512324511281262"
    filehash = "acbc775087da23725c3d783311d5f5083c93658de392c17994a9151447ac2b63"
    
  strings:
    $str1 = "l6gzro1rswkqbk6tinxnkuylv" ascii wide 
    $str2 = "iv78c1cg" ascii wide
    $str3 = "lky2lit5lpthkcscfnz3f91oa" ascii wide
    $str4 = "gwpkys9h" ascii wide
    $bs641 = "l6gzro1rswkqbk6tinxnkuylv" base64
    $bs642 = "iv78c1cg" base64
    $bs643 = "lky2lit5lpthkcscfnz3f91oa" base64
    $bs644 = "gwpkys9h" base64
    $code1 = "Ww2Z3pybzFyc3drcWJrNnRpbnhua3V5bHY"
    $code2 = "aXY3OGMxY2c"
    $code3 = "bGt5MmxpdDVscHRoa2NzY2ZuejNmOTFvYS"
    $code4 = "1nd3BreXM5aC"

  condition:
    any of them
    and filesize < 500KB
}


