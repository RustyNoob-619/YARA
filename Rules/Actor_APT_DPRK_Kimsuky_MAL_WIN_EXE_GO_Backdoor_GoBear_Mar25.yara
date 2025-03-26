
import "pe"

rule Actor_APT_DPRK_Kimsuky_MAL_WIN_EXE_GO_Backdoor_GoBear_Mar25
{
    meta:
        rule_id = "83bdf010-4986-4ca4-96cb-8fd36d8afcec"
        date = "25-03-2025"
        author = "RustyNoob619"
        description = "Detects a Signed Backdoor written in GO called GoBear used by DPRK APT Kimsuky"
        source = "https://zhuanlan.zhihu.com/p/680534132"
        filehash = "a8c24a3e54a4b323973f61630c92ecaad067598ef2547350c9d108bc175774b9"

    condition:
        pe.signatures[0].thumbprint == "30db7d678045e44d882d7652ba6aaa6593c02328" //D2innovation Co.,LTD
        and pe.imphash() == "d910780e43eb6473c6ca334d8a16a8af" //Needs Validation
        and filesize < 11MB

}