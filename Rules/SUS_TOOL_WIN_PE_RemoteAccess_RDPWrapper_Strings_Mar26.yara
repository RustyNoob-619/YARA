
rule SUS_TOOL_WIN_PE_RemoteAccess_RDPWrapper_Strings_Mar26
{
    meta:
        rule_id = "1d5355d8-26cd-447e-a402-68f046ca14de"
        date = "15-03-2026"
        author = "Rustynoob619"
        description = "Detects a legitimate remote access tool known as RDPWrapper that is used by threat actors during post exploitation"
        source = "https://www.genians.co.kr/en/blog/threat_intelligence/kakaotalk"
        filehash = "798af20db39280f90a1d35f2ac2c1d62124d1f5218a2a0fa29d87a13340bd3e4"

    strings:
        $dll1 = "SvchostPushServiceGlobals" ascii fullword
        $dll2 = "ServiceMain" ascii fullword 
        
        $rdp1 = "rdpwrap.ini" wide fullword
        $rdp2 = "rdpwrap.txt" wide fullword
        $rdp3 = "\\rdpwrap.txt" wide fullword
        $rdp4 = "RDPWrap" wide fullword
        $rdp5 = "rdpwrap.dll" wide fullword

    condition:
        uint16(0) == 0x5a4d
        and all of ($dll*)
        and 2 of ($rdp*)
        and filesize < 500KB

}
