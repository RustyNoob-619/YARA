import "pe"

rule Actor_CRIME_TAG124_MAL_WIN_EXE_Loader_CleanUpLoader_CodeSignCerts_FEB25
{
  meta:
    author = "RustyNoob619"
    description = "Detects a loader called CleanUpLoader used by a TDS tracked as TAG-124 based on Code Sign Certificates"
    source = "https://www.recordedfuture.com/research/tag-124-multi-layered-tds-infrastructure-extensive-user-base"
    filehash = "183c57d9af82964bfbb06fbb0690140d3f367d46d870e290e2583659609b19f2"

  condition:
    (pe.signatures[0].thumbprint == "36a0f423c1fa48f172e4fecd06b8099f0ebbaeb8" or
    pe.signatures[0].thumbprint == "3889079227eedd36b4dd7604157d7f7186b5b741" or
    pe.signatures[0].thumbprint == "7ed7081ee612fbf9fe0ade46f4a2749da20251e0") 
    and filesize < 150KB
}

