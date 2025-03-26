import "elf"

rule File_LNX_ELF_UPX_Packed_JAN25
{
  meta:
    author = "RustyNoob619"
    description = "Detects ELF samples that are packed with the UPX packer based on the sections in the file"
    filehash = "e5e475db5076e112f69b61ccb36aaedfbb7cac54a03a4a2b3c6a4a9317af2196"
  
  condition:
    for any section in elf.sections:
    (section.name startswith ".upx")
}

rule Actor_APT_CN_APT41_LNX_ELF_Backdoor_KeyPlug_JAN25
{
  meta:
    author = "RustyNoob619"
    description = "Detects Linux variant of the Key Plug backdoor used by Chinese threat group APT41"
    filehash = "e5e475db5076e112f69b61ccb36aaedfbb7cac54a03a4a2b3c6a4a9317af2196"
    reference = "https://x.com/Cyberteam008/status/1876819353611411963"
  
  condition:
    elf.telfhash() == "t156213580ed3e5b9616e15d78cc542be3819396baa121db14ff98ddc0886e10af360d2e" // Requires testing with YARA ELF module 
    and filesize < 5MB   
}

