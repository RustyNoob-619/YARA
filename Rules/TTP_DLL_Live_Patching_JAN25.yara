
rule TTP_AMSI_DLL_Live_Patching_JAN25
{
  meta:
    author = "RustyNoob619$"
    description1 = "Detects paching the ASMI interface to bypass the security features of the Windows OS. TTP is based on sus API calls & parameters"
    description2 = "The AmsiScanBuffer() function is key component of AMSI on Windows which allows applications to submit data to be scanned by installed AV software"
    example = "8693e1c6995ca06b43d44e11495dc24d809579fe8c3c3896e972e2292e4c7abd"
    reference = "https://isc.sans.edu/diary/Live+Patching+DLLs+with+Python/31218"
    credit = "Xavier Mertens @xme for explaining the internal workings of the TTP"
    
  strings:
    $amsifunc = "AmsiScanBuffer" ascii wide
    $apis1 = "GetProcAddress" ascii wide
    $apis2 = "LoadLibraryA" ascii wide
    $apis3 = "RtlMoveMemory" ascii wide

  condition:
    TTP_Memory_Permissions_Tampering
    and $amsifunc
    and 2 of ($api*)
}

rule TTP_ETW_DLL_Live_Patching_JAN25
{
  meta:
    author = "RustyNoob619$"
    description1 = "Detects paching the ASMI interface to bypass the security features of the Windows OS. TTP is based on sus API calls & parameters"
    description2 = "The EtwEventWrite() function in Windows is a core component of the ETW framework. It allows applications to log events that can be captured and analysed for debugging, performance monitoring & security auditing."
    example = "8693e1c6995ca06b43d44e11495dc24d809579fe8c3c3896e972e2292e4c7abd"
    reference = "https://isc.sans.edu/diary/Live+Patching+DLLs+with+Python/31218"
    credit = "Xavier Mertens @xme for the explaining internal workings of the TTP"
    
  strings:
    $etwfunc = "EtwEventWrite" ascii wide
    $apis1 = "GetProcAddress" ascii wide
    $apis2 = "LoadLibraryA" ascii wide
    $apis3 = "RtlMoveMemory" ascii wide

  condition:
    TTP_Memory_Permissions_Tampering
    and $etwfunc
    and 2 of ($api*)
}

