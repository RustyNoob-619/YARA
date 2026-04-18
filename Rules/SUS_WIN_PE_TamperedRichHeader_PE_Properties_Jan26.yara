import "pe"
import "math"

rule SUS_WIN_PE_TamperedRichHeader_PE_Properties_Jan26
{
    meta:
        rule_id = "0678a71c-e8c9-4dba-93b6-342d1ad07dd9"
        date = "04-01-2026"
        author = "Rustynoob619"
        description = "Detects Windows PE files with potentially duplicated Rich headers. This is based on the fact that there can only exist unique pairs of ProdIDs and Build numbers. Hence, the overall enthropy or randomness should be high"
        source = "https://www.virusbulletin.com/virusbulletin/2020/01/vb2019-paper-rich-headers-leveraging-mysterious-artifact-pe-format/"

    condition:
        uint16(0) == 0x5a4d
        and pe.rich_signature.length > 0
        and math.entropy(pe.rich_signature.clear_data) < 1
        and filesize < 10MB 
}
