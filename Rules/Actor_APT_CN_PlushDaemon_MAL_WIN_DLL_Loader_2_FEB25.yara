import "pe"

rule Actor_APT_CN_PlushDaemon_MAL_WIN_DLL_Loader_2_FEB25
{
  meta:
    author = "RustyNoob619"
    description = "Detects the loader DLL used by an unknown Chinese APT called PlushDaemon based on PE properties"
    source = "https://www.welivesecurity.com/en/eset-research/plushdaemon-compromises-supply-chain-korean-vpn-service/"
    filehash = "9c82ccddbf3d542a48c4950a82b4f5913c7be9c8e757ba5b78f6ed59979b7fa6"
    
  strings:
    $wide1 = "C:\\windows\\explorer.exe" wide fullword
    $wide2 = "RuntimeSvc.exe" wide fullword
    $wide3 = "PerfWatson.exe" wide fullword
    $wide4 = "Elevation:Administrator!new:%s" wide fullword

    $str1 = "\\Microsoft Shared\\Filters\\SystemInfo\\winlogin.gif"
    $str2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"
    $str3 = "svcghost.exe"
    
  condition:
    ((pe.pdb_path contains "D:\\project\\vs\\zx\\ServiceSvc\\Release\\")
    or
    (uint16be(0) == 0x4d5a  
    and pe.exports("CreateFileReadAble")
    and pe.exports("FlvMetaCreateObject")
    and pe.exports("FlvWriter_WriteHeader")
    and pe.exports("Flv_WriteTag")
    and pe.exports("GetFLVInfo")
    and any of ($wide*)
    and any of ($str*)))
    and filesize < 1MB
}


