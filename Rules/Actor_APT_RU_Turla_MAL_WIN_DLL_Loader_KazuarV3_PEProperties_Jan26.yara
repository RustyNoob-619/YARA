import "pe"

rule Actor_APT_RU_Turla_MAL_WIN_DLL_Loader_KazuarV3_PEProperties_Jan26
{
    meta:
        rule_id = "f9a3799f-1ee1-4876-bbc9-9ec8c4e40e37"
        date = "25-01-2026"
        author = "Rustynoob619"
        description = "Detects Kazuar V3 loader used by Russian APT Turla based on PE properties"
        source = "https://r136a1.dev/2026/01/14/command-and-evade-turlas-kazuar-v3-loader/"
        credit = "@TheEnergyStory for the analysis and sharing of the malware hashes"
        filehash = "69908f05b436bd97baae56296bf9b9e734486516f9bb9938c2b8752e152315d4"

    condition:
        uint16(0) == 0x5a4d
        and pe.imports("SHELL32.dll","InitNetworkAddressControl")
        and (
            pe.exports("Fxmbrfqx") or
            pe.exports("Iotnj") or
            pe.exports("Qtupnngh") or
            pe.exports("Waoqmz")
            )
        and filesize < 250KB
}
