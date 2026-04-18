import "pe"

rule MAL_TOOL_WIN_PE_RemoteAccess_RDPWrapper_Strings_Mar26
{
    meta:
        rule_id = "2ab38566-0101-421c-9427-c7eecabb83c3"
        date = "16-03-2026"
        author = "Rustynoob619"
        description = "Detects a legitimate remote access tool known as RDPWrapper that is used by threat actors based on known malicious PE import hashes"
        source = "https://www.genians.co.kr/en/blog/threat_intelligence/kakaotalk"
        filehash = "798af20db39280f90a1d35f2ac2c1d62124d1f5218a2a0fa29d87a13340bd3e4"

    condition:
        uint16(0) == 0x5a4d
        and (
            pe.imphash() == "a89655faa2b6840e801be1e1c779fc67" or
            pe.imphash() == "53a3dacee6717ddc12074523c645029b" 
            )
        and filesize < 2MB

}
