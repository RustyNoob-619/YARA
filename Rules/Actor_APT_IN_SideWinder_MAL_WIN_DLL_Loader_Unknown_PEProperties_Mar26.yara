import "pe"

rule Actor_APT_IN_SideWinder_MAL_WIN_DLL_Loader_Unknown_PEProperties_Mar26
{
    meta:
        rule_id = "31d3bca0-1dff-4848-ac6d-a0ec16143b69"
        date = "03-03-2026"
        author = "RustyNoob619"
        description = "Detects a loader DLL used by Indian APT SideWinder based on PE properties"
        source = "https://arcticwolf.com/resources/blog/sloppylemming-deploys-burrowshell-and-rust-based-rat-to-target-pakistan-and-bangladesh/"
        filehash = "81d1a62c00724c1dfbc05a79ac4ae921c459350a2a4a93366c0842fadc40b011"
        
    condition:
        uint16(0) == 0x5a4d
        and (pe.imphash() == "48897a3c3804c4736ab6fd488347e535"
        or (
            pe.rich_signature.toolid(0x101, 33145) == 5 and 
            pe.rich_signature.toolid(0x104, 35221) == 2 and 
            pe.rich_signature.toolid(0x100, 35221) == 1 and
            pe.rich_signature.toolid(0x102, 35221) == 1
        )
        or (pe.number_of_exports == 1
        and pe.exports("CorInitSvcLogger")))
        and filesize < 50KB 

}
