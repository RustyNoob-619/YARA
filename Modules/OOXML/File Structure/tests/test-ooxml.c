
#include <yara.h>
#include "util.h"

int main(int argc, char** argv)
{
  int result = 0;

  YR_DEBUG_INITIALIZE();
  YR_DEBUG_FPRINTF(1, stderr, "+ %s() { // in %s\n", __FUNCTION__, argv[0]);

  init_top_srcdir();

  yr_initialize();
  
  assert_true_rule_file(
      "import \"ooxml\" \
      rule test_1 { \
        meta: \
        file_hash = \"4bad3e34a192a8f305e188538b4370ea835446cc6ba32fe046d9a5f2bc3df172\" \
        description = \"check if on disk central dir entries is equal to total entries\" \
        condition: \
          ooxml.is_ooxml \
          and ooxml.number_of_on_disk_entries == ooxml.number_of_total_entries \
      }",
      "tests/data/"
      "4bad3e34a192a8f305e188538b4370ea835446cc6ba32fe046d9a5f2bc3df172.doc");
      
  assert_true_rule_file(
      "import \"ooxml\" \
      rule test_2 { \
        meta: \
        file_hash = \"4bad3e34a192a8f305e188538b4370ea835446cc6ba32fe046d9a5f2bc3df172\" \
        description = \"check range and equality of central dir size and offset respectively\" \
        condition: \
          ooxml.is_ooxml \
          and ooxml.central_dir_size < 1KB \
          and ooxml.central_dir_offset == 0x3220 \
      }",
      "tests/data/"
      "4bad3e34a192a8f305e188538b4370ea835446cc6ba32fe046d9a5f2bc3df172.doc");
      
  assert_true_rule_file(
      "import \"ooxml\" \
      rule test_3 { \
        meta: \
        file_hash = \"4bad3e34a192a8f305e188538b4370ea835446cc6ba32fe046d9a5f2bc3df172\" \
        description = \"check for null zip comment length\" \
        condition: \
          ooxml.is_ooxml \
          and ooxml.zip_comment_len == 0 \
      }",
      "tests/data/"
      "4bad3e34a192a8f305e188538b4370ea835446cc6ba32fe046d9a5f2bc3df172.doc");
  
  assert_true_rule_file(
      "import \"ooxml\" \
      rule test_4 { \
        meta: \
        file_hash = \"4bad3e34a192a8f305e188538b4370ea835446cc6ba32fe046d9a5f2bc3df172\" \
        description = \"test basic iteration of central dir entries. Check for image files in any entries\" \
        condition: \
          ooxml.is_ooxml \
          and for any entry in ooxml.entries: \
          (entry.name_string contains \"image\") \
      }",
      "tests/data/"
      "4bad3e34a192a8f305e188538b4370ea835446cc6ba32fe046d9a5f2bc3df172.doc");
  
  assert_true_rule_file(
      "import \"ooxml\" \
      rule test_5 { \
        meta: \
        file_hash = \"4bad3e34a192a8f305e188538b4370ea835446cc6ba32fe046d9a5f2bc3df172\" \
        description = \"manual check of the Content_Types.xml without the use of is_ooxml at second entry\" \
        condition: \
          ooxml.entries[1].name_string == \"[Content_Types].xml\" \
          and ooxml.entries[1].name_length == 19 \
      }",
      "tests/data/"
      "4bad3e34a192a8f305e188538b4370ea835446cc6ba32fe046d9a5f2bc3df172.doc");
      
  assert_true_rule_file(
      "import \"ooxml\" \
      rule test_6 { \
        meta: \
        file_hash = \"4bad3e34a192a8f305e188538b4370ea835446cc6ba32fe046d9a5f2bc3df172\" \
        description = \"check for uncompressed size greater than compressed size of any entry\" \
        condition: \
          ooxml.is_ooxml \
          and for any entry in ooxml.entries: \
          (entry.compressed_size > 0 and entry.uncompressed_size > entry.compressed_size) \
      }",
      "tests/data/"
      "4bad3e34a192a8f305e188538b4370ea835446cc6ba32fe046d9a5f2bc3df172.doc");
      
  assert_true_rule_file(
      "import \"ooxml\" \
      rule test_7 { \
        meta: \
        file_hash = \"4bad3e34a192a8f305e188538b4370ea835446cc6ba32fe046d9a5f2bc3df172\" \
        description = \"test for a specific CRC32 Checksum value match at last entry\" \
        condition: \
          ooxml.is_ooxml \
          and ooxml.entries[ooxml.number_of_total_entries - 1].crc32_checksum == 0x4CE962CA \
      }",
      "tests/data/"
      "4bad3e34a192a8f305e188538b4370ea835446cc6ba32fe046d9a5f2bc3df172.doc");
      
  assert_true_rule_file(
      "import \"ooxml\" \
      rule test_8 { \
        meta: \
        file_hash = \"4bad3e34a192a8f305e188538b4370ea835446cc6ba32fe046d9a5f2bc3df172\" \
        description = \"Test mapping of compression method raw value and corresponding method name\" \
        condition: \
          ooxml.is_ooxml \
          and ooxml.entries[3].compression_method_value == 8 \
          and ooxml.entries[3].compression_method_name == \"Deflate\" \
      }",
      "tests/data/"
      "4bad3e34a192a8f305e188538b4370ea835446cc6ba32fe046d9a5f2bc3df172.doc");
      
  assert_true_rule_file(
      "import \"ooxml\" \
      rule test_9 { \
        meta: \
        file_hash = \"4bad3e34a192a8f305e188538b4370ea835446cc6ba32fe046d9a5f2bc3df172\" \
        description = \"check for flags value of any entry equal to zero \" \
        condition: \
          ooxml.is_ooxml \
          and for any entry in ooxml.entries: \
          (entry.flags == 0) \
      }",
      "tests/data/"
      "4bad3e34a192a8f305e188538b4370ea835446cc6ba32fe046d9a5f2bc3df172.doc");
  
  assert_true_rule_file(
      "import \"ooxml\" \
      rule test_10 { \
        meta: \
        file_hash = \"4bad3e34a192a8f305e188538b4370ea835446cc6ba32fe046d9a5f2bc3df172\" \
        description = \"Check if the ZIP specification version and the ZIP version needed are equal to a given value. Also check if the raw value of version made is parsed correctly \" \
        condition: \
          ooxml.is_ooxml \
          and ooxml.entries[5].version_made_by == 788  \
          and ooxml.entries[5].os_name == \"Unix\" \
          and ooxml.entries[5].spec_version == 20 \
          and ooxml.entries[5].spec_version == ooxml.entries[5].version_needed \
      }",
      "tests/data/"
      "4bad3e34a192a8f305e188538b4370ea835446cc6ba32fe046d9a5f2bc3df172.doc");
      
  assert_false_rule(
      "import \"ooxml\" \
      rule test_11 { \
        meta: \
        file_hash = \"4bad3e34a192a8f305e188538b4370ea835446cc6ba32fe046d9a5f2bc3df172\" \
        description = \"check those PKZIP files which are not OOXML \" \
        condition: \
          ooxml.is_ooxml \
          and ooxml.number_of_total_entries > 0  \
      }",
      "tests/data/"
      "4bad3e34a192a8f305e188538b4370ea835446cc6ba32fe046d9a5f2bc3df172.doc");


  yr_finalize();

  YR_DEBUG_FPRINTF(
      1, stderr, "} = %d // %s() in %s\n", result, __FUNCTION__, argv[0]);

  return result;
}
