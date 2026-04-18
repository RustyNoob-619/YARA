rule Actor_APT_DPRK_Konni_TOOL_WIN_PE_RemoteAccess_RDPWrapper_PEProperties_Mar26
{
    meta:
        rule_id = "02dee1b4-58dc-4111-9484-7995f903d08f"
        date = "17-03-2026"
        author = "Rustynoob619"
        description = "Detects legitimate remote access tool known as RDP Wrapper with configuration linked to DPRK APT Konni based on observed config parameters"
        source = "https://www.genians.co.kr/en/blog/threat_intelligence/kakaotalk"
        filehash = "ac92d4c6397eb4451095949ac485ef4ec38501d7bb6f475419529ae67e297753"

    strings:
        $rdp1 = "rdpwrap.ini" wide fullword
        $rdp2 = "rdpwrap.txt" wide fullword
        $rdp3 = "\\rdpwrap.txt" wide fullword
        $rdp4 = "RDPWrap" wide fullword
        $rdp5 = "rdpwrap.dll" wide fullword

        $cli = "RDPWInst.exe [-l|-i[-s][-o]|-w|-u[-k]|-r]" wide

        $sys1 = "netsh advfirewall firewall add rule name=\"Remote Desktop\" dir=in protocol=tcp localport=3389 profile=any action=allow" ascii wide
        $sys2 = "\\system32\\reg.exe\" add HKLM\\SYSTEM\\CurrentControlSet\\Services\\TermService\\Parameters /v ServiceDll /t REG_EXPAND_SZ /d \"" ascii wide
    
        $pol1 = "TerminalServices-RemoteConnectionManager-AllowMultipleSessions=1" ascii wide
        $pol2 = "TerminalServices-RemoteConnectionManager-MaxUserSessions=0" ascii wide

    condition:
        uint16(0) == 0x5a4d
        and 2 of ($rdp*)
        and $cli
        and all of ($sys*)
        and all of ($pol*)
        and filesize < 2MB

}
