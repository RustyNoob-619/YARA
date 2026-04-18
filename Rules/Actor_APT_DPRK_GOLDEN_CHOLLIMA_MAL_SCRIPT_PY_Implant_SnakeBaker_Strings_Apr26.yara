
rule Actor_APT_DPRK_GOLDEN_CHOLLIMA_MAL_SCRIPT_PY_Implant_SnakeBaker_Strings_Apr26
{
    meta:
        rule_id = "ec7006f4-3195-45f5-99f1-483d81da4d08"
        date = "04-04-2026"
        author = "Rustynoob619"
        description = "Detects SnakeBaker Python Script used by DPRK APT GOLDEN CHOLLIMA based on observed strings"
        source = "https://www.crowdstrike.com/en-us/blog/labyrinth-chollima-evolves-into-three-adversaries/"
        filehash = "b6995c31a7ee88392fc25fd6d1a3a7975b3cb4ec3a9a318c3fcfaaf89eb65ce1"
    
    strings:
        $13rot = "rot13" ascii 

        $exec1 = "exec(compile" ascii
        $exec2 = "platform.system()" ascii
        $exec3 = "base64.b64decode" ascii
        $exec4 = "codecs.decode" ascii
        $exec5 = "response.status_code" ascii

        $rot1 = "Jvaqbjf" ascii 
        $rot2 = "Tbbtyr.pbz" ascii 
        $rot3 = "uggcf://nxnznvgrpuabybtvrf.bayvar/" ascii

    condition:
        #13rot > 3
        and 3 of ($exec*)
        and any of ($rot*)
        and filesize < 50KB
}
