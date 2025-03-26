import "pe"

rule Actor_CRIME_TAG124_MAL_WIN_EXE_Loader_CleanUpLoader_strings_FEB25
{
  meta:
    author = "RustyNoob619"
    description = "Detects a loader called CleanUpLoader used by a TDS tracked as TAG-124 based on Code Sign Certificates"
    source = "https://www.recordedfuture.com/research/tag-124-multi-layered-tds-infrastructure-extensive-user-base"
    filehash = "183c57d9af82964bfbb06fbb0690140d3f367d46d870e290e2583659609b19f2"

  strings:
    $str1 = "fatalitiespaywareparallelogram" ascii fullword
    $str2 = "stymieinternationalmegaphones" ascii fullword
    $str3 = "ideologicallysyntheses" ascii fullword
    $str4 = "dispatchamphibiouscertainty" ascii fullword
    $str5 = "preferbirettasunclasps" ascii fullword
    $str6 = "carpentervocalizesBrubeck" ascii fullword
    $str7 = "circumspectmiserabledeleverages" ascii fullword
    $str8 = "daddytransfigures" ascii fullword
    $str9 = "aggravatesfinalitysnorkelled" ascii fullword
    $str10 = "titmicediabetesdallies" ascii fullword
    $str11 = "beneficentlycrueller" ascii fullword
    $str12 = "ravenousconquistadornightfall" ascii fullword
    $str13 = "initializedPravdaincautious" ascii fullword
    $str14 = "piquedcodesallspice" ascii fullword
    $str15 = "activistjocosesquirmier" ascii fullword
    $str16 = "cocoasmaintainedinvective" ascii fullword
    $str17 = "playerbonfiresunquestionable" ascii fullword
    $str18 = "imprisonedhiresoutcroppings" ascii fullword
    $str19 = "vigilantismplacebogroused" ascii fullword
    $str20 = "whimperedreedsprocurers" ascii fullword
    $str21 = "protestationsdestineMoslems" ascii fullword
    $str22 = "Exodusclutteredsimpleton" ascii fullword
    $str23 = "irritationsoilclothSacajawea" ascii fullword
    $str24 = "resemblingexemplifyinghefts" ascii fullword
    $str25 = "TheodosiusweightlifterTaoist" ascii fullword
    $str26 = "hyperactivityachievers" ascii fullword
    $str27 = "mistakenlysleazieremulsions" ascii fullword
    $str28 = "brutallytitillatingconcerns" ascii fullword
    $str29 = "governingLockeancomings" ascii fullword 
    $str30 = "monetizedtrotsmonochrome" ascii fullword
    $str31 = "bullymilitarizeplonking" ascii fullword
    $str32 = "devilmagnetsnonpareil" ascii fullword
    $str33 = "BrahmaputraPricelineannealed" ascii fullword
    $str34 = "unforgettableIslamistlaunderers" ascii fullword
    $str35 = "foolishlylividlyMashhad" ascii fullword
    
  condition:
    uint16(0) == 0x5a4d
    and 10 of them 
    and filesize < 150KB
}

