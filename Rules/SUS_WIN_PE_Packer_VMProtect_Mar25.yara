
import "pe"

rule SUS_WIN_PE_Packer_VMProtect_Mar25
{
    meta:
        rule_id = "f67c24d8-ff84-41ba-92c7-92b7c964254e"
        date = "25-03-2025"
        author = "RustyNoob619"
        description = "Detects Windows files packed using VMProtect"
        source = "https://www.f-secure.com/v-descs/vmprotect.shtml"
        filehash = "61b8fbea8c0dfa337eb7ff978124ddf496d0c5f29bcb5672f3bd3d6bf832ac92"

    condition:
        pe.sections[pe.number_of_sections-2].name contains "vmp"
        and filesize < 25MB
}