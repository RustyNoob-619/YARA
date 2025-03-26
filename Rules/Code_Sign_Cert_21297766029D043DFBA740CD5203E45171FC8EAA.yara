import "pe"

rule Code_Sign_Cert_21297766029D043DFBA740CD5203E45171FC8EAA
{
  meta:
    author = "RustyNoob619"
    description = "Detects malware samples that are signed with T H SUPPORT SERVICES LTD (thumbprint - 21297766029D043DFBA740CD5203E45171FC8EAA)"
    reference = "https://x.com/SquiblydooBlog/status/1878033443516535052"
    credit = "@SquiblydooBlog for sharing the sample and the code signing certificate"
    filehash = "24a26ac9cd209bf84831dae7d778fceb46b1e30b48454c130a6e62accdc1369e"
  condition:
    pe.number_of_signatures > 0
    and pe.signatures[0].thumbprint == "21297766029d043dfba740cd5203e45171fc8eaa" // Code Sign Cert of T H SUPPORT SERVICES LTD
}


