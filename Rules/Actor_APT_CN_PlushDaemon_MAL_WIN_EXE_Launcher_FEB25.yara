import "pe"

rule Actor_APT_CN_PlushDaemon_MAL_WIN_EXE_Launcher_FEB25
{
  meta:
    author = "RustyNoob619"
    description = "Detects the executable that launches other components to side load DLL used by an unknown Chinese APT called PlushDaemon based on PE properties"
    source = "https://www.welivesecurity.com/en/eset-research/plushdaemon-compromises-supply-chain-korean-vpn-service/"
    filehash = "062264c360b05c6b8a3598b8cd13c72e6cd3b9e34c4ae2c7fc272659599434c3"
    
  strings:
    $wide1 = "Only Run Go Window Class1233" wide fullword
    $wide2 = "explorer.exe" wide fullword

    $fls1 = "FlsFree" ascii fullword
    $fls2 = "FlsSetValue" ascii fullword
    $fls3 = "FlsGetValue" ascii fullword
    $fls4 = "FlsAlloc" ascii fullword

    $str1 = "\\Microsoft Shared\\Filters\\SystemInfo\\Winse.gif"
    $str2 = "cmd.exe /c %s %s" 

    $http1 = "HTTP/1.1 200 OK" ascii fullword
    $http2 = "Content-Type: text/javascript" ascii fullword
    $http3 = "Content-Length: 0" ascii fullword
    $http4 = "Connection: close" ascii fullword
    
  condition:
    ((pe.pdb_path contains "D:\\project\\vs\\zx\\ServiceSvc\\Release\\ProcessMonitor.pdb")
    or
    (uint16be(0) == 0x4d5a  
    and any of ($wide*)
    and any of ($fls*)
    and any of ($str*)
    and 3 of ($http*)))
    and filesize < 100KB
}




