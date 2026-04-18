import "lnk"

rule Actor_APT_DPRK_APT37_MAL_WIN_LNK_Loader_Unknown_PEProperties_Mar26
{
    meta:
        rule_id = "44ad0cb4-f68f-441a-bbd2-197bbdbdffd3"
        date = "11-03-2026"
        author = "Rustynoob619"
        description = "Detects RESTLEAF loader used by APT37 (Inky Squid) based on PE properties"
        source = "https://www.zscaler.com/blogs/security-research/apt37-adds-new-capabilities-air-gapped-networks"
        filehash = "c07e0f01e39ae74667d3014904706b50effd1f3cb75e8130eb57729d38589ad5"

    condition:
        uint32be(0) == 0x4c000000
        and lnk.cmd_line_args startswith "/c for /f \"tokens=*\" %a"
        and lnk.cmd_line_args contains "do start /min"
        and lnk.cmd_line_args contains "-ExecutionPolicy Bypass"
        and lnk.cmd_line_args contains "-WindowStyle Hidden"
        and lnk.cmd_line_args contains "[Array]::Copy("
        and lnk.cmd_line_args contains "[System.IO.Path]::Combine("
        and lnk.cmd_line_args contains "[System.Text.Encoding]::UTF8.GetString"
        and lnk.cmd_line_args endswith ";exit\""
        and filesize > 500KB and filesize < 2MB

}
