import "pe"

rule SUS_WIN_PE_InvalidRichHeader_Version_PE_Properties_Jan26
{
    meta:
        rule_id = "0ebb7470-3b8f-453f-addb-cb43c255be27"
        date = "02-01-2026"
        author = "Rustynoob619"
        description = "Detects Windows PE files with invalid ProdIDs of the PE Rich Header. This is one of the most common anomalies in rich headers"
        source = "https://github.com/dishather/richprint/blob/master/comp_id.txt"

    condition:
        uint16(0) == 0x5a4d
        and pe.rich_signature.length > 0
        and for any rich_val in pe.rich_signature.tools: (
            rich_val.toolid > 270 //Most Recent Product ID value {0x010e} for prodidUtc1900_POGO_O_CPP
        )
        and filesize > 10KB and filesize < 10MB 
}
