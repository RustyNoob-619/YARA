import "pe"

rule Actor_APT_Silver_Fox_MAL_WIN_FirstStage_DLL_RAT_VAllyRAT_3_FEB25
{
  meta:
    author = "RustyNoob619"
    description = "Detects first stage DLL that contributes to deployment of ValleyRAT based on strings and PE properties"
    source = "https://www.morphisec.com/blog/rat-race-valleyrat-malware-china/?utm_content=323764605&utm_medium=social&utm_source=twitter&hss_channel=tw-2965779277"
    filehash = "bb89e401560ba763d1c5860dd51667ba17768c04d00270bf34abebac47fd040e"

  strings:
    $pydll = "python227.dll" ascii fullword

    $str1 = "f:\\dd\\vctools\\crt_bld\\self_x86\\crt\\src\\locale0.cpp" 
    $str2 = "f:\\dd\\vctools\\crt_bld\\self_x86\\crt\\src\\xutility"  
    $str3 = "f:\\dd\\vctools\\crt_bld\\self_x86\\crt\\src\\read.c"
    $str4 = "f:\\dd\\vctools\\crt_bld\\self_x86\\crt\\src\\osfinfo.c"
    
  condition:
    (pe.imphash() == "a61fc581354f9c20a3245e0d70cc4af5" or $pydll)
    or 
    (2 of ($str*)
    and pe.exports("Msg")
    and pe.exports("g_pMemAlloc"))
    and filesize < 1MB
    
}

