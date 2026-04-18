import "pe"

rule Actor_APT_IN_MysteriousElephant_MAL_WIN_DLL_Extractor_Uplo_PEProperties_Mar26
{
    meta:
        rule_id = "31880f18-8131-4f46-9dde-157e020d9b10"
        date = "23-03-2026"
        author = "Rustynoob619"
        description = "Detects Uplo Extractor tool used by Indian APT Mysterious Elephant based on PE Exports"
        source = "https://securelist.com/mysterious-elephant-apt-ttps-and-tools/117596/"
        filehash = "715935bfd6d3eec9adedcc50968250a8b75ab0395936c92916d79a5cc3ab7027"

    condition:
        uint16(0) == 0x5a4d
        and pe.number_of_exports < 5
        and pe.exports("SxTracerDebuggerBreak")
        and pe.exports("SxTracerGetThreadContextRetail")
        and pe.exports("SxTracerShouldTrackFailure")
        and filesize < 1MB

}
