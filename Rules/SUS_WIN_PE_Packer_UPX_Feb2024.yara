import "pe"

rule SUS_WIN_PE_Packer_UPX_Feb2024
{
    meta:
        author = "RustyNoob619"
        description = "Detects the use of the UPX Packer in an executable"

   condition:
       for any resource in pe.resources:
       (resource.name startswith "UPX")

}




