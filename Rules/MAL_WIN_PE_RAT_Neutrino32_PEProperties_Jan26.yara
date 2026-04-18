import "pe"

rule MAL_WIN_PE_RAT_Neutrino32_PEProperties_Jan26
{
    meta:
        rule_id = "e9164520-dd80-48b3-b083-d94e733b5b14"
        date = "11-01-2026"
        author = "Rustynoob619"
        description = "Detects Neutrino malware based on PE Rich header properties"
        source = "https://web.archive.org/web/20191223034907/http://blog.ptsecurity.com/2019/08/finding-neutrino.html"
        filehash = "229467c797351586197bdd34c2deb9a83260f7d911cc0df4e6027b68e59ec56a"

    condition:
        uint16(0) == 0x5a4d
        and (pe.rich_signature.toolid(0x00af) == 47 or pe.rich_signature.toolid(0x00af) == 16)
        and pe.rich_signature.toolid(0x000a) == 11
        and pe.rich_signature.toolid(0x000e) == 2
        and pe.rich_signature.toolid(0x0004, 8168) == 2
        and filesize < 500KB
}
