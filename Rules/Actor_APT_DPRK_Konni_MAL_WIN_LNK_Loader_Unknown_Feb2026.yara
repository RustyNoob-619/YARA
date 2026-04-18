rule Actor_APT_DPRK_Konni_MAL_WIN_LNK_Loader_Unknown_Feb2026
{
    meta:
        rule_id = "4769666f-4740-496e-993d-8288d05260f1" 
        date = "2026-02-17" 
        author = "Rustynoob619" 
        description = "Detects LNK files acting as a loader for docx and cab files used by APRK APT Konni" 
        source = "https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/" 
        filehash = "c94e58f134c26c3dc25f69e4da81d75cbf4b4235bcfb40b17754da5fe07aad0a"

    strings:
        $pad = "RUEQWQYQQQ"

        $spec = "mw_decrypt_portion_of_lnk" wide nocase 

        $cmd1 = "-windowstyle hidden" wide nocase
        $cmd2 = "$param_decryption_key" wide nocase
        $cmd3 = "$buffer -Encoding" wide nocase
        $cmd4 = "-W hidden function" wide nocase
        $cmd5 = "-bxor" wide nocase
        $cmd6 = "-encoding byte" wide nocase
        $cmd7 = "-recurse -erroraction silentlycontinue" wide nocase

        $file1 = ".docx" wide nocase
        $file2 = ".cab" wide nocase

    condition:
        uint32be(0) == 0x4C000000
        and #pad > 5
        and (
            $spec
            or (
            4 of ($cmd*)
            and all of ($file*)
            )
        ) 
        and filesize < 250KB 
}
