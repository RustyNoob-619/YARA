
import "pe"

rule MAL_WIN_PE_ICS_Industroyer_PE_Properties_Jan26
{
    meta:
        rule_id = "6d10b8c6-057d-4860-a193-e11b350ada32"
        date = "07-01-2026"
        author = "Rustynoob619"
        description = "Detects Industroyer malware based on the count of specific PE Rich header Prod IDs"
        source = "https://www.virusbulletin.com/virusbulletin/2020/01/vb2019-paper-rich-headers-leveraging-mysterious-artifact-pe-format/"
        filehash = "3e3ab9674142dec46ce389e9e759b6484e847f5c1e1fc682fc638fc837c13571"
    
    condition:
        uint16(0) == 0x5a4d 
        pe.rich_signature.toolid(0x00f1) == 9
        and pe.rich_signature.toolid(0x00f1) == 9
        and pe.rich_signature.toolid(0x00f3) == 120
        and pe.rich_signature.toolid(0x00f2) == 24
        and pe.rich_signature.toolid(0x00f1) == 9
        and pe.rich_signature.toolid(0x0105) == 29
        and pe.rich_signature.toolid(0x0104) == 17
        and filesize < 500KB
    }
