import "pe"

rule Actor_APT_CN_MustangPanda_MAL_WIN_DLL_Backdoor_LOTUSLITE_PEProperties_Jan26
{
    meta:
        rule_id = "4456fa3c-b7b9-4bdd-a315-cd86ba12d792"
        date = "27-01-2026"
        author = "Rustynoob619"
        description = "Detects LOTUSLITE backdoor used by Chinese APT Mustang Panda based on PE Properties"
        source = "https://www.acronis.com/en/tru/posts/lotuslite-targeted-espionage-leveraging-geopolitical-themes/"
        filehash = "2c34b47ee7d271326cfff9701377277b05ec4654753b31c89be622e80d225250"

    condition:
        uint16(0) == 0x5a4d
        and pe.number_of_signatures == 0
        and pe.number_of_exports > 10
        and pe.exports("KugouMain")
        and (
            pe.exports("QRTAPI_CleanupRepository") or
            pe.exports("QRTAPI_GetLastError") or
            pe.exports("QRTAPI_Initialize") or
            pe.exports("QRTAPI_Uninitialize")
        )
        and filesize < 500KB
}
