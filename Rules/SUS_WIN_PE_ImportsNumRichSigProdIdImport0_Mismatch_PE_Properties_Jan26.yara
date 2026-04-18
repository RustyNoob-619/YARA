
import "pe"

rule SUS_WIN_PE_ImportsNumRichSigProdIdImport0_Mismatch_PE_Properties_Jan26
{
    meta:
        rule_id = "b623b3f8-5e4f-41d8-8f17-1ec51f07173c"
        date = "06-01-2026"
        author = "Rustynoob619"
        description = "Detects Windows PE files where there is a mismatch between the number of PE imports and the ProdIDImport0 tool id count which also indicates the number of PE imports"
        source = "https://www.virusbulletin.com/virusbulletin/2020/01/vb2019-paper-rich-headers-leveraging-mysterious-artifact-pe-format/"
        FP1 = "79674328b5e9c92f57c8d58f431d55fac8554b0c27f06bd6323a841851012d1b"

    condition:
        uint16(0) == 0x5A4D 
        and pe.rich_signature.toolid(0) > 0
        and (pe.number_of_imports - pe.rich_signature.toolid(1)) > 20
        and filesize < 10MB

}







