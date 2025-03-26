import "pe"

rule Actor_APT_CN_PlushDaemon_MAL_WIN_DLL_Loader_1_FEB25
{
  meta:
    author = "RustyNoob619"
    description = "Detects the initial loader DLL used by an unknown Chinese APT called PlushDaemon based on PE properties"
    source = "https://www.welivesecurity.com/en/eset-research/plushdaemon-compromises-supply-chain-korean-vpn-service/"
    filehash = "a7c715caa806f92b8aea8fc4431ecd0bee091b498edcb6f1b8cdb41f1561fcdb"
    
  strings:
    $str1 = "packages\\ENCMgr.pkg" ascii fullword
    $str2 = "//tmp.bak" ascii fullword
    
  condition:
    ((pe.pdb_path == "D:\\project\\vs\\zx\\ServiceSvc\\Release\\VSPMsg.pdb")
    or
    (uint16be(0) == 0x4d5a  
    and pe.exports("CreateCompilerFactory")
    and pe.exports("GetMessageDll")
    and pe.exports("GetXSPHeap")
    and pe.exports("LoadLibraryUsingFullPath")
    and pe.exports("XspLogEvent")
    and any of them))
    and filesize < 150KB
}


