import "pe"

rule SUS_WIN_PE_HeaderRichLinkerMismatch_Version_PE_Properties_Jan26
{
    meta:
        rule_id = "4b10aaed-dbdf-4e74-96e9-9ce80f5929c7"
        date = "01-01-2026"
        author = "RustyNoob619"
        description = "Detects files using modern tool chains with older linkers which can indicate possible tampering. It is based on the mismatch in the PE RICH header and Optional header MSVC linker versions"
        source = "https://github.com/dishather/richprint/blob/master/comp_id.txt"
        filehash = "849959ded166f92706aa84fd93f1720c6f241c78d0c3089cf1934d9a251e3f46"

    condition:
        uint16(0) == 0x5a4d 
        not pe.imports("mscoree.dll") // Ignore .NET
        and pe.rich_signature.length > 0 // Check for Rich header presence
        and pe.linker_version.major == 14 // MSVC 14.X version
        and for any tool in pe.rich_signature.tools: ( // Iterate through various RICH Headers 

            tool.version > 10000 and tool.version < 22000
            // 22000 set to avoid versions in range of MSVS Community 2015 [14.0] (23026) & MSVS2026 v18.3.0 (35721)
           //  1000  set to avoid MSVS2002 (.NET) 7.0.9466 (9466)

        )
        and filesize < 10MB

}
