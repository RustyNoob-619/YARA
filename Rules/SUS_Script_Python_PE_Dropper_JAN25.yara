
rule SUS_Script_Python_PE_Dropper_JAN25
{
  meta:
    author = "RustyNoob619$"
    description = "Detects Python scripts that contain embedded Windows PE payloads"
    filehash = "8693e1c6995ca06b43d44e11495dc24d809579fe8c3c3896e972e2292e4c7abd" // Python Script dropps Swaet RAT, a .NET RAT as the next stage payload
    reference = "https://isc.sans.edu/diary/31554"
    credit = "Xavier Mertens @xme for sharing the file hash and analysis of the Python Script"
   
  condition:
    File_Format_Script_Python
    and TTP_Embedded_PE_Base64
    //and TTP_AMSI_DLL_Live_Patching
    //and TTP_ETW_DLL_Live_Patching
    and filesize < 250KB

}

