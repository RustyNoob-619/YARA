
rule Actor_APT_EarthEstries_MAL_Backdoor_HemiGate_RC4_Mar25 
{
    meta:
        rule_id = "d769b5fb-5483-482b-aee8-d3d950d9da4c"
        date = "23-03-2025"
        author = "RustyNoob619"
        description = "Detects the Encrypted Payload linked to HemiGate Backdoor used by APT Earth Estries based on used RC4 key"
        source = "https://www.trendmicro.com/en_gb/research/23/h/earth-estries-targets-government-tech-for-cyberespionage.html"
        filehash1 = "4b014891df3348a76750563ae10b70721e028381f3964930d2dd49b9597ffac3"
        filehash2 = "51d5ff50848001b693902006725b9fc605f7db6cddd3c4a68280eec4f2c05910"

    strings:
      $RC4_1 = {34 33 37 36 64 73 79 67 64 59 54 46 64 65 33}
      $RC4_2 = {34 00 33 00 37  00 36 00 64 00 73 00 79 00 67 00 64 00 59 00 54 00 46 00 64 00 65 00 33}
      $RC4_3 = "4376dsygdYTFde3" ascii wide

    condition:
      any of them 
      and filesize < 500KB 
}

