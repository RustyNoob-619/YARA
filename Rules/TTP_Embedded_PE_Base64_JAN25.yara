
rule TTP_Embedded_PE_Base64_JAN25
{
  meta:
    author = "RustyNoob619$"
    description = "Detects Windows PE fiels embedded in other files as Base64 encoded payloads"
    example = "8693e1c6995ca06b43d44e11495dc24d809579fe8c3c3896e972e2292e4c7abd"
    
  strings:
    $base64pe1 = "TVq" //Base64 for MZ
    $base64pe2 = "VGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGU" // Base64 for This program cannot be run in DOS mode.
    $base64pe3 = "BQRQ" //Base64 for PE

  condition:
    all of them 
    and @base64pe3 > @base64pe2
    and @base64pe2 > @base64pe1
}


