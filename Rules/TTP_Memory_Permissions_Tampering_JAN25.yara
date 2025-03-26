
rule TTP_Memory_Permissions_Tampering_JAN25
{
  meta:
    author = "RustyNoob619$"
    description = "Detects tampering of memory protection flags concerning permissions and API calls which is typically used in code injection or unpacking"
    example = "8693e1c6995ca06b43d44e11495dc24d809579fe8c3c3896e972e2292e4c7abd"
    
  strings:
    $protectflg = "0x40" fullword ascii wide
    $protectvalue = "PAGE_READ_WRITE_EXECUTE" ascii wide
    $api = "VirtualProtect" ascii wide

  condition:
    any of ($protect*)
    and $api
}

