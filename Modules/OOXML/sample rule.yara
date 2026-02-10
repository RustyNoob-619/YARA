import "ooxml"

rule test_ooxml_module_1
{
    meta:
    file_hash = "4bad3e34a192a8f305e188538b4370ea835446cc6ba32fe046d9a5f2bc3df172"
    description = "check if on disk central dir entries is equal to total entries"
    condition:
        ooxml.is_ooxml
        and ooxml.number_of_on_disk_entries == ooxml.number_of_total_entries

}

rule test_ooxml_module_2
{
    meta:
    file_hash = "4bad3e34a192a8f305e188538b4370ea835446cc6ba32fe046d9a5f2bc3df172"
    description = "check range and equality of central dir size and offset respectively"
    condition:
        ooxml.is_ooxml
        and ooxml.central_dir_size < 1KB
        and ooxml.central_dir_offset == 0x3220

}

rule test_ooxml_module_3
{
    meta:
    file_hash = "4bad3e34a192a8f305e188538b4370ea835446cc6ba32fe046d9a5f2bc3df172"
    description = "check for non-null zip comment length"
    condition:
        ooxml.is_ooxml
        and ooxml.zip_comment_len == 0 //change again

}

rule test_ooxml_module_4
{
    meta:
    file_hash = "4bad3e34a192a8f305e188538b4370ea835446cc6ba32fe046d9a5f2bc3df172"
    description = "testing basic iteration of central dir entries. Check for .PNG files in any of the entries"
    condition:
        ooxml.is_ooxml
        and for any entry in ooxml.entries:
        (entry.name_string contains "image") //change again

}

rule test_ooxml_module_5
{
    meta:
    file_hash = "4bad3e34a192a8f305e188538b4370ea835446cc6ba32fe046d9a5f2bc3df172"
    description = "manual check of the Content_Types.xml without the use of is_ooxml at the second entry"
    condition:
        ooxml.entries[1].name_string == "[Content_Types].xml"
        and ooxml.entries[1].name_length == 19

}

rule test_ooxml_module_6
{
    meta:
    file_hash = "4bad3e34a192a8f305e188538b4370ea835446cc6ba32fe046d9a5f2bc3df172"
    description = "check for uncompressed size greater than compressed size of any entry"
    condition:
        ooxml.is_ooxml
        and for any entry in ooxml.entries:
        (entry.compressed_size > 0 and entry.uncompressed_size > entry.compressed_size)

}

rule test_ooxml_module_7
{
    meta:
    file_hash = "4bad3e34a192a8f305e188538b4370ea835446cc6ba32fe046d9a5f2bc3df172"
    description = "test for a specific CRC32 Checksum value match at last entry"
    condition:
        ooxml.is_ooxml
        and ooxml.entries[ooxml.number_of_total_entries - 1].crc32_checksum == 0x4CE962CA

}

rule test_ooxml_module_8
{
    meta:
    file_hash = "4bad3e34a192a8f305e188538b4370ea835446cc6ba32fe046d9a5f2bc3df172"
    description = "Test mapping of compression method raw value and corresponding method name"
    condition:
        ooxml.is_ooxml
        and ooxml.entries[3].compression_method_value == 8
        and ooxml.entries[3].compression_method_name == "Deflate"

}

rule test_ooxml_module_9
{
    meta:
    file_hash = "4bad3e34a192a8f305e188538b4370ea835446cc6ba32fe046d9a5f2bc3df172"
    description = "check for flags value of any entry equal to zero "
    condition:
        ooxml.is_ooxml
        and for any entry in ooxml.entries:
        (entry.flags == 0)

}

rule test_ooxml_module_10
{
    meta:
    file_hash = "4bad3e34a192a8f305e188538b4370ea835446cc6ba32fe046d9a5f2bc3df172"
    description = "Check if the ZIP specification version and the ZIP version needed are equal to a given value. Also check if the raw value of version made is parsed correctly"
    condition:
        ooxml.is_ooxml
        and ooxml.entries[5].version_made_by == 788 //0x0314
        and ooxml.entries[5].os_name == "Unix" //Upper Byte 0x03 -> Unix
        and ooxml.entries[5].spec_version == 20 //Lower Byte 0x14 -> int 20 -> 2.0
        and ooxml.entries[5].spec_version == ooxml.entries[5].version_needed

}

rule test_false_ooxml_module_1
{
    meta:
    file_hash = "4bad3e34a192a8f305e188538b4370ea835446cc6ba32fe046d9a5f2bc3df172"
    description = "check those PKZIP files which are not OOXML"
    condition:
        not ooxml.is_ooxml
        and ooxml.number_of_total_entries > 0
        
}
