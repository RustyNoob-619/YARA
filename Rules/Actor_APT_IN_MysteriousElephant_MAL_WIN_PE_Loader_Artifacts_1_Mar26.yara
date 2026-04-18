rule Actor_APT_IN_MysteriousElephant_MAL_WIN_PE_Loader_Artifacts_1_Mar26
{
    meta:
        rule_id = "ebaba2fc-5263-43db-a6c3-25fc06082aa5"
        date = "22-03-2026"
        author = "Rustynoob619"
        description = "Detects Windows malware used by Indian APT Mysterious Elephant based on observed artifacts"
        source = "https://securelist.com/mysterious-elephant-apt-ttps-and-tools/117596/"
        filehash = "f2798e228979842a16057072efc5f58d790bd4649802536ad1189b5714cb85e9"

    
    strings:
        $desk = "MalwareTech_Hidden" ascii fullword

        $rc4 = "D12Q4GXl1SmaZv3hKEzdAhvdBkpWpwcmSpcD" ascii wide

    condition:
        uint16(0) == 0x5a4d
        and any of them
        and filesize < 1MB

}
