
rule MAL_MAC_MachO_Stealer_MacSync_CodeSignCert_Jan26
{
    meta:
        rule_id = "4d91308a-a9e8-466a-abc0-128a62a8958f"
        date = "12-01-2026"
        author = "Rustynoob619"
        description = "Detects MacSync Stealer based on TeamID used to sign the certificate"
        source = "https://www.jamf.com/blog/macsync-stealer-evolution-code-signed-swift-malware-analysis/"
        filehash = "9990457feac0cd85f450e60c268ddf5789ed4ac81022b0d7c3021d7208ebccd3"

    strings:
        $teamid = {47 4e 4a 4c 53 33 55 59 5a 34 31 [9] 32 44 65 76 65 6c 6f 70 65 72 20 49 44} 

    condition:
        (uint32(0) == 0xfeedfacf or uint32(0) == 0xbebafeca)
        and $teamid
        and filesize < 500KB

}

