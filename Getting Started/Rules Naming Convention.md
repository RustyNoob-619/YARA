# Rule Naming Convention 

The naming convention is a revised version of Florian Roth's YARA Style Guide available here: https://github.com/Neo23x0/YARA-Style-Guide

## YARA Rule Name Syntax

The following syntax is a suggested one and depends on what the rule is for, certain fields might be eliminated. For instance, if a rule is written for malware that is NOT associated with known actor groups, then the first part of the name containing Intention_ActorType_CountryCode_ActorName can be removed and the rule name will be the following: 
*Intention_OSType_Technology_MalwareType_MalwareName_RuleDate*

Likewise, if a rule is aimed at detecting known threat actors rather than the malware related to them. This could be based on properties that are specific to threat actor strings,  PE properties, complier time stamps, stolen code signing certificates and others. In such scenarios, it is essential to clearly specify in the description field what artifacts the rule is based on the rule name might look like this: *Intention_ActorType_ActorName_OptionalArtifacts_RuleDate*

**Setup**
The recommended method to write YARA is using the VS Code Editor. There is a custom VS Code Snippet Generator that will populate the YARA template according to our requirements, please use it. The instructions to install it are in the file itself. It can be found under the following link:
/YARA/Utilities/VS_Code_Snippet_Code_Gen.json

**Intention_ActorType_CountryCode_ActorName_OSType_Technology_MalwareType_MalwareName_RuleDate**

## YARA Rule Name Examples

1. Actor_APT_RU_CozyBear_MAL_LNX_ELF_Loader_Mirai_Apr18 - YARA rule written in April 2018 for a Linux malware called Mirai that is used by APT Cozybear. Note that in this example the intention is repeated twice for APT and MAL.
2. MAL_WIN_EXE_Backdoor_BRC4_Feb25 - YARA rule written in February 2025 for a Malware of type backdoor targeting Windows OS known as BRC4.
3. Actor_APT_RU_APT28_Code_Sign_Cert_Feb25 - YARA rule written in February 2025 to detect APT28 files based on the artifact code signing certificate. 

### Intention
- Actor
- MAL (For Malware)
- TTP
- Packer
- Tool

### OS Type
- WIN - Windows
- LNX - Linux
- MAC - Macos

### Technology
- EXE
- DLL
- SYS
- ELF
- LNK
- ZIP
- RAR
- Script_X where X is PY, JS, VBS, PS
- NET, GO, Rust
- Docs like PDF, DOC,EXCEL

### Malware Type
- Loader
- Backdoor
- Infostealer
- Downloader
- Dropper
- Exploit_CVE_ID
- Ransomware
- RAT (Remote Access Trojan)
- Rootkit

### Malware Name
Examples:
- PLugX
- QakBot
- EasyStealer

### Actor Type
- APT - For Nation State
- CRIME - For Cybercrime Groups
- HACK - Hacktivist  

### Actor Country Code Shorthand
- RU - Russia
- DPRK - North Korea
- CN - China

### Actor Name
Examples:
- APT28
- BR-UNC-003
- EasyStealer

### Optional Artifacts
- Strings
- PE properties
- Complier time stamps
- Stolen code signing certificates
- PDB Paths

### Suffix: Rule Date
Simple format using the Month followed by Year. 
Example: _Nov25 
