import "pe"

rule MAL_WIN_PE_Unknown_CodeSignCert001_Feb26
{
    meta:
        rule_id = "9bd197ee-875f-49ce-9843-e90467cecf9c"
        date = "11-02-2026" 
        author = "Rustynoob619"
        description = "Detects malware signed using an expired code signing certificate Anneng electronic Co. Ltd."
        source = "https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/"
        filehash1 = "f9dd0b57a5c133ca0c4cab3cca1ac8debdc4a798b452167a1e5af78653af00c1"
        filehash2 = "859db05738c5692a0522e1a392b027fa40b4e429093c6cd66b60fe7b23ab5199"

    condition:
        pe.number_of_signatures > 0
        and (
            // Anneng electronic Co. Ltd.
            pe.signatures[0].serial == "26:02:bb:9b:a2:ae:65:1a:ea:a7:9a:ec:38:a3:cb:3d"
            // Guangzhou Kingteller Technology Co., Ltd.
            or pe.signatures[0].serial == "08:01:cc:11:eb:4d:1d:33:1e:3d:54:0c:55:a4:9f:7f"
        )
}
