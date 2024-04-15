import "pe"
// naming convention for YARA rules: File Type, General type, Malware type, Malware name and date
rule Dll_Backdoor_FalseFront_Jan2024 {
    meta:
        Description = "Identifies a backdoor known as FalseFront which was used by Peach Sandstorm"
        Author = "RustyNoob619"
        Reference = "https://twitter.com/Now_on_VT/status/1744989481831174173, https://twitter.com/MsftSecIntel/status/1737895717870440609"
        Credits = "Is Now on VT! for notificaiton of the VT sample on Twitter and for and to Microsoft Threat Intelligence for sharing the intel"
        Hash = "364275326bbfc4a3b89233dabdaf3230a3d149ab774678342a40644ad9f8d614"
    condition:
    pe.pdb_path == "D:\\a\\_work\\1\\s\\artifacts\\obj\\coreclr\\windows.x64.Release\\Corehost.Static\\singlefilehost.pdb" //not a rare PDB path
    and pe.imphash() == "68031a2b11c02bee00a0a687110994be" // remove this for broader matching
    and pe.dll_name == "singlefilehost.exe"
    and pe.number_of_exports == 5
    and pe.number_of_delayed_imported_functions == 5
    and pe.number_of_delayed_imports == 2
    and for 2 section in pe.sections:
    (section.name == ".CLR_UEF" or section.name == ".didat")  
    and for all export in pe.export_details:
    (export.name == "g_CLREngineMetrics"
    or export.name == "CLRJitAttachState"
    or export.name == "DotNetRuntimeInfo"
    or export.name == "MetaDataGetDispenser"
    or export.name == "g_dacTable")                          
    and for 2 resource in pe.resources:
    (resource.name_string == "C\x00L\x00R\x00D\x00E\x00B\x00U\x00G\x00I\x00N\x00F\x00O\x00"
    or resource.name_string == "M\x00I\x00N\x00I\x00D\x00U\x00M\x00P\x00_\x00E\x00M\x00B\x00E\x00D\x00D\x00E\x00D\x00_\x00A\x00U\x00X\x00I\x00L\x00I\x00A\x00R\x00Y\x00_\x00P\x00R\x00O\x00V\x00I\x00D\x00E\x00R\x00")
 }

//Note: This rule will be updated later to reduce the false positives  
