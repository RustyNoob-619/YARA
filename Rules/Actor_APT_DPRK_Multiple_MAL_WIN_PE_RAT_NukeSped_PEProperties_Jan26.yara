import "pe"

rule Actor_APT_DPRK_Multiple_MAL_WIN_PE_RAT_NukeSped_PEProperties_Jan26
{
    meta:
        rule_id = "bdfa6514-cd89-4d2a-833e-f696466beadf"
        date = "09-01-2026"
        author = "Rustynoob619"
        description = "Detects NukeSped used by various DPRK APTs based on PE Rich header properties"
        source = "https://www.fortinet.com/blog/threat-research/deep-analysis-nukesped-rat"
        filehash = "ff2eb800ff16745fc13c216ff6d5cc2de99466244393f67ab6ea6f8189ae01dd"

    condition:
        uint16(0) == 0x5a4d
        and pe.rich_signature.length > 0
        and pe.rich_signature.toolid(0x000a) > 100 and pe.rich_signature.toolid(0x000a) < 110
        and (pe.rich_signature.toolid(0x000b) > 7 or pe.rich_signature.toolid(0x000b) < 15)
        and (pe.rich_signature.version(4035) == 9 or pe.rich_signature.version(4035) == 13)
        and (pe.rich_signature.version(7299) > 17 and pe.rich_signature.version(7299) < 25)
        and filesize < 2MB
}
