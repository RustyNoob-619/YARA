private rule TTP_PowerShell_execution_JAN25
  {strings:
    $pwrshll = "powershell.exe" ascii wide 
    $pwrshllparam1 = "system.net.webclient" ascii wide
    $pwrshllparam2 = "-exec bypass" ascii wide
    $pwrshllparam3 = "-w hidden -nop" ascii wide

  condition:
    $pwrshll and any of ($pwrshllparam*)}

private rule TTP_VBS_Script_embedded
{strings:
    $vbsexec = "<SCRIPT language=\"VBScript\">" ascii wide fullword 
    
  condition:
    $vbsexec}

private rule TTP_WScript_Shell_execution
{strings:
    $wscript = "createobject(\"WScript.Shell\")" ascii wide
    
  condition:
    $wscript}

private rule TTP_Base64_encoding_usage
{strings:
    $base64 = "base64" nocase
    
  condition:
    $base64}

private rule Header_File_HTA
{strings:
    $html= {3c 21 44 4f	43 54 59 50	45 20 68 74	6d 6c 3e 0a}
    
  condition:
    $html at 0}

private rule Header_File_LNK
{strings:
    $lnk = {4C 00 00 00 01 14 02 00}
    
  condition:
    $lnk at 0}

private rule Header_File_VBS
{condition:
    uint32be(0) == 0x64696d20} //dim

private rule APT_RU_UAC0099_attributes
{strings:
    $usragnt = "Ds26GOZNxbTxlJY" ascii wide
    $c2url = "https://newyorktlimes.life/api/values"
    
  condition:
    any of them}

private rule File_Path_C_Users_Public_Docs
{strings:
    $vbspath1 = "C:\\\\Users\\\\Public\\\\Documents\\\\" ascii wide
    $vbspath2 = "C:\\Users\\Public\\Documents\\" ascii wide
    
  condition:
    any of them}

private rule Scheduled_Tasks_ExplorerCoreUpdateTaskMachine
{strings:
    $schtsks = "schtasks.exe /create /TN ExplorerCoreUpdateTaskMachine" ascii wide
    $schtsksparams = "/SC minute /mo 3 /tr"
    
  condition:
    all of them}

rule HTA_APT_RU_UAC0099_strings
{ 
  meta:
    author = "RustyNoob619"
    description = "Detects HTA file used as the first stage in a campaign against Ukraine Gov Entities between NOV & DEC 2024"
    source = "https://cert.gov.ua/article/6281681"
    filehash = "88b64a3eb0dc38e3f8288b977b1cd67af7d4ba959297ac48ef5f06bec3e77560"

  condition:
    Header_File_HTA
    and (APT_RU_UAC0099_attributes
    or 
    (TTP_VBS_Script_embedded
    and TTP_WScript_Shell_execution
    and TTP_Base64_encoding_usage
    and TTP_PowerShell_execution
    and File_Path_C_Users_Public_Docs
    and Scheduled_Tasks_ExplorerCoreUpdateTaskMachine))
    and filesize < 25KB
    }

rule LNK_APT_RU_UAC0099_strings
{
  meta:
    author = "RustyNoob619"
    description = "Detects LNK file used as the first stage in a campaign against Ukraine Gov Entities between NOV & DEC 2024"
    source = "https://cert.gov.ua/article/6281681"
    filehash = "cd2eb07158cbc56db4979dd0ef8e73b5c06929d8eeb5af717210b2d53df94fbf"

  condition:
    Header_File_LNK
    and (APT_RU_UAC0099_attributes
    or 
    (TTP_Base64_encoding_usage
    and TTP_PowerShell_execution
    and File_Path_C_Users_Public_Docs
    and Scheduled_Tasks_ExplorerCoreUpdateTaskMachine))
    and filesize < 25KB
    }

rule VBS_APT_RU_UAC0099_strings
{ 
  meta:
    author = "RustyNoob619"
    description = "Detects VBS script used as the first stage in a campaign against Ukraine Gov Entities between NOV & DEC 2024"
    source = "https://cert.gov.ua/article/6281681"
    filehash1 = "0f05990ef107e49b59bc8d736cdd9535e514efb18e5246fb2b7dc2b7d3305784"
    filehash2 = "71aac82441162ed0a61d30a75d057402adcce4e1a81e61941a41a0385c7e7b0b"

  condition:
    Header_File_VBS 
    and (APT_RU_UAC0099_attributes
    or 
    (TTP_WScript_Shell_execution
    and TTP_PowerShell_execution
    and File_Path_C_Users_Public_Docs))
    and filesize < 5KB
    }












