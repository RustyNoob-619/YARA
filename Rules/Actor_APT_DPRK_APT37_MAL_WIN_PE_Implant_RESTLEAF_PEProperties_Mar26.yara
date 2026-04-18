
import "pe"

rule Actor_APT_DPRK_APT37_MAL_WIN_PE_Implant_RESTLEAF_PEProperties_Mar26
{
    meta:
        rule_id = "f4705370-ef41-4c43-87c2-3fc59b975e6b"
        date = "12-03-2026"
        author = "Rustynoob619"
        description = "Detects RESTLEAF loader used by APT37 (Inky Squid) based on PE properties"
        source = "https://www.zscaler.com/blogs/security-research/apt37-adds-new-capabilities-air-gapped-networks"
        filehash = "cf2e3f46b26bae3d11ab6c2957009bc1295b81463dd67989075592e81149c8ec"

    condition:
        uint16(0) == 0x5a4d
        and (pe.imphash() == "a4fb2de7d2bf27dff63aaafd62a891e1" or pe.pdb_path == "D:\\test\\RestApi\\Win32\\Release\\RestApi.pdb")
        and filesize < 1MB

}
