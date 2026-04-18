
import "pe"

rule MAL_WIN_PE_RichSignature_Offset_PE_Properties_Jan26
{
    meta:
        rule_id = "56120808-f912-4a16-99ae-92fb8daffae1"
        date = "07-01-2026"
        author = "Rustynoob619"
        description = "Detects Windows PE files that have rich signatures on non-standard offset. These offsets are associated with known malware"
        source = "https://github.com/dishather/richprint/blob/master/comp_id.txt"
    
    condition:
        uint16(0) == 0x5a4d 
        and pe.rich_signature.length > 0
        and (
            pe.rich_signature.offset == 0x60
            or pe.rich_signature.offset == 0x68
            or pe.rich_signature.offset == 0x8C
            or pe.rich_signature.offset == 0xE0
            )
}


