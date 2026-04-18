import "pe"

rule SUS_WIN_PE_InvalidRichHeaderXORKey_PE_Properties_Jan26
{
    meta:
        rule_id = "c180ee2e-2325-47d5-8848-2cdabfee14bb"
        date = "05-01-2026"
        author = "Rustynoob619"
        description = "Detects Windows PE files with where the XOR key is set to invalid values such as all zeros or padding or if there is a DanS marker mismatch with the XOR key"
        source = "https://www.virusbulletin.com/virusbulletin/2020/01/vb2019-paper-rich-headers-leveraging-mysterious-artifact-pe-format/"

    condition:
        uint16(0) == 0x5a4d
        and pe.rich_signature.length > 0
        and (
            pe.rich_signature.key == 0x00000000 
            or pe.rich_signature.key == 0xCCCCCCCC
            or (uint32(pe.rich_signature.offset) != (pe.rich_signature.key ^ 0x536E6144)) //DanS in HEX
            ) 
        and filesize < 10MB 
}
