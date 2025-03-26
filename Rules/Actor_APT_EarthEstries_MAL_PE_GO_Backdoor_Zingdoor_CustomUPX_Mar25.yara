
rule Actor_APT_EarthEstries_MAL_PE_GO_Backdoor_Zingdoor_CustomUPX_Mar25 
{
    meta:
        rule_id = "08de938c-b20e-40c8-8092-51e9cfb79add"
        date = "23-03-2025"
        author = "RustyNoob619"
        description = "Detects a Backdoor known as Zingdoor used by APT Earth Estries based on the modified UPX header"
        source = "https://www.trendmicro.com/en_gb/research/23/h/earth-estries-targets-government-tech-for-cyberespionage.html"
        filehash1 = "efb98b8f882ac84332e7dfdc996a081d1c5e6189ad726f8f8afec5d36a20a730" //Not Available on VT
        filehash2 = "8476ad68ce54b458217ab165d66a899d764eae3ad30196f35d2ff20d3f398523" //Not Available on VT
        filehash3 = "42d4eb7f04111631891379c5cce55480d2d9d2ef8feaf1075e1aed0c52df4bb9" //Not Available on VT
        filehash4 = "dff1d282e754f378ef00fb6ebe9944fee6607d9ee24ec3ca643da27f27520ac3" //Not Available on VT

    strings:
      $UPX0 = {00 4d 53 45 30 00}
      $UPX1 = {00 4d 53 45 31 00}
      $UPX2 = {33 2e 39 34 00 4d 53 45 21}

    condition:
      uint16(0) == 0x5a4d 
      and all of ($UPX*)  
      and filesize < 1MB 
}
