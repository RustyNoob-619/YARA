import "pe"

rule Actor_CRIME_TAG124_MAL_WIN_EXE_Loader_CleanUpLoader_ImportHashes_FEB25
{
  meta:
    author = "RustyNoob619"
    description = "Detects a loader called CleanUpLoader used by a TDS tracked as TAG-124 based on PE import hashes"
    source = "https://www.recordedfuture.com/research/tag-124-multi-layered-tds-infrastructure-extensive-user-base"
    filehash = "183c57d9af82964bfbb06fbb0690140d3f367d46d870e290e2583659609b19f2"

  condition:
    (pe.imphash() == "970725500d4c590551cb7610a5fb002e" or 
    pe.imphash() == "402a7a8f1ff45b12e0afa00837a1eb95" or
    pe.imphash() == "53d593988216ec8b3661b29884893869" or
    pe.imphash() == "9381fac21d123f58be042e824570a08a" or
    pe.imphash() == "73f7a9e2a615cd87aa4419f5e5460ab7" or
    pe.imphash() == "9016ab5e603e914b642534bff0b0109e" or
    pe.imphash() == "0382bba929f930114dd744dea05f507a" or
    pe.imphash() == "9381fac21d123f58be042e824570a08a") 
    and filesize < 150KB
}
