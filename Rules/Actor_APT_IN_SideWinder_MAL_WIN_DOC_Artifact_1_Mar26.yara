
rule Actor_APT_IN_SideWinder_MAL_WIN_DOC_Artifact_1_Mar26
{
    meta:
        rule_id = "14af50d5-a966-4b7c-9b2a-2c7fe592ad16"
        date = "07-03-2026"
        author = "Rustynoob619"
        description = "Detects malicious docs used by Indian APT SideWinder based on observed image artifacts"
        source = "https://x.com/wa1Ile/status/2031612431856971936"
        filehash = "0c9a8ce9516edb686faf2bee4bd9dc3285207031fe5f2f742accf4a525518d8e"

    strings:
        $img1 = "word/media/deer.jpg" ascii
        $img2 = "word/media/rhino.jpg" ascii
        
    condition:
        uint32be(0) == 0x504b0304
        and any of them
        and filesize < 750KB 

}
