import "pe"
  
rule Actor_APT_DPRK_Multiple_MAL_WIN_DLL_RAT_NukeSped64_PEProperties_Jan26
{
    meta:
        rule_id = "df2fbbbe-9740-433d-ba15-4410fa0325eb"
        date = "10-01-2026"
        author = "Rustynoob619"
        description = "Detects NukeSped used by various DPRK APTs based on PE Rich header properties"
        source = "https://www.fortinet.com/blog/threat-research/deep-analysis-nukesped-rat"
        filehash = "229467c797351586197bdd34c2deb9a83260f7d911cc0df4e6027b68e59ec56a"

    condition:
        uint16(0) == 0x5a4d
        and pe.rich_signature.length > 0
        and pe.rich_signature.version(21005) > 0
        and pe.exports("ExtractMicrosoftWord")
        and filesize < 500KB
}
