import "pe"

rule MAL_WIN_DLL_Delphi_RAT_Unkown_FEB25
{
  meta:
    author = "RustyNoob619"
    description = "Detects an unkown RAT written in Delphi based on PE attributes"
    credit = "@dodo_sec for sharing the malware sample"
    source = "https://x.com/dodo_sec/status/1884752244286886119"
    filehash = "c22708013a643dd1a07524eea50c4be8f50e6770a628bc1114a112b1384ca403"
    
  strings:
    $delphi1 = "Software\\Borland\\Locales" wide fullword
    $delphi2 = "Software\\Borland\\Delphi\\Locales" wide fullword
    $delphi3 = "DelphiRM_GetObjectInstance" wide fullword
    $delphi4 = "DelphiApp" wide fullword
    $delphi5 = "Delphi Picture" wide fullword
    $delphi6 = "Delphi Component" wide fullword
    
    $wide1 = "HKEY_CLASSES_ROOT" wide fullword
    $wide2 = "HKEY_CURRENT_USER" wide fullword
    $wide3 = "HKEY_LOCAL_MACHINE" wide fullword
    $wide4 = "HKEY_USERS" wide fullword
    $wide5 = "HKEY_PERFORMANCE_DATA" wide fullword
    $wide6 = "HKEY_CURRENT_CONFIG" wide fullword
    $wide7 = "HKEY_DYN_DATA" wide fullword
    
  condition:
    ((pe.imphash() == "965b93fc2a14fa377f26437242f9e2c2")
    or
    (pe.locale(0x0813) // Dutch - Belgium
    and pe.exports("mozilla_dump_image")
    and pe.exports("SoundTouch_V7")
    and pe.exports("workerlz4_compress")
    and pe.exports("DumpJSStack")
    and any of ($delphi*)
    and 3 of ($str*)))
    and filesize < 15MB
}
