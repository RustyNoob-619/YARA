import "pe"

rule SUS_WIN_PE_ExecutableResourceSection_Version_PE_Properties_Jan26
{
    meta:
        rule_id = "de4e2fab-5bee-4dd7-b1e0-7c66886cf6fa"
        date = "02-01-2026"
        author = "Rustynoob619"
        description = "Detects Windows PE files that have executable resource section which can hint towards stego-loading or packing from resource"
        note = "might trigger FPs on older WinRAR or SFX stubs"
        filehash = "bb8a613da3537750e82ef2e2f662c0dbe0a036cdcf80756c5cbbca713cdb8ac4"

    condition:
        uint16(0) == 0x5A4D and
        for any section in pe.sections: (
                section.name == ".rsrc" and
                (section.characteristics & pe.SECTION_MEM_EXECUTE) //EXE Flag = 0x20000000
            )
        and not pe.version_info["OriginalFilename"] == "iKernel.dll" //Remove one of the FPs
        and filesize < 5MB

}
