OOXML YARA module is used to parse OOXML file formats that are typically found in modern documents. The module is based on the PKZIP specification since OOXML files are ZIP archives.

Below are the instructions to install this module in YARA. The module has been tested on YARA 4.5.4. For details on the module usage and functions, please see ooxml.md file here: https://github.com/RustyNoob-619/YARA/blob/main/Modules/OOXML/File%20Structure/docs/modules/ooxml.md

There is a simple and short version of this installation which only requires ooxml.c, ooxml.h and changes to module_list, MakeFile.am

**NOTE:** The files in the File Structure folder on this repository are arranged based on where they are located in your YARA directory.

Navigate to the File Structure folder and add the following files to their respective locations in your YARA root directory:

- ooxml.c: add to yara-4.5.x => libyara => modules => ooxml -> ooxml.c

- ooxml.h: add to yara-4.5.x => libyara => include => yara -> ooxml.h

- test-ooxml.c: add to yara-4.5.x => tests -> test-ooxml.c

- ooxml.md: add to yara-4.5.x => docs => modules -> ooxml.md

The below three files already exist in your YARA directory, you can either modify them or paste over the entire files. It is recommended to simply edit the existing files as different versions of YARA might have varying file content. For reference, both the original and modified versions of these three files have also been added to the File Structure folder. You can simply search for *ooxml* in MOD_filename within the File Structure folder in the repo to see where changes need to be made.

**NOTE:** Please ensure that the indentation is correct to avoid any compile time errors.

1. Navigate to yara-4.5.x => libyara => modules -> modules_list and add the following lines to the end of the file

```
#ifdef OOXML_MODULE
MODULE(ooxml)
#endif
```

2. Navigate to yara-4.5.x -> MakeFile.am and add the following lines in three different sections of the file. Search for similar module names and insert the lines accordingly.

//During the first few sections in the file
```
if OOXML_MODULE
MODULES += libyara/modules/ooxml/ooxml.c
endif
```
//Towards end of the file, search for *check_PROGRAMS =* and insert the below anywhere in between
```
test-ooxml \
```
//Towards end of the file, add the below lines
```
if OOXML_MODULE
check_PROGRAMS+=test-ooxml
test_ooxml_SOURCES = tests/test-ooxml.c tests/util.c
test_ooxml_LDADD = libyara.la
test_ooxml_LDFLAGS = -static
endif
```
3. Navigate to yara-4.5.x -> configure.ac and add the following lines in two different sections in the file. Search for similar module names and insert the lines accordingly.
//Towards first half of the file
```
AC_ARG_ENABLE([ooxml],
  [AS_HELP_STRING([--enable-ooxml], [enable ooxml module])],
  [if test x$enableval = xyes; then
    build_ooxml_module=true
    CFLAGS="$CFLAGS -DOOXML_MODULE"
  fi])
```
//Towards end of the file
```
AM_CONDITIONAL([OOXML_MODULE], [test x$build_ooxml_module = xtrue])
```

After pasting the above files in their respective directories, run the following commands from your YARA root directory:

**NOTE:** You might need to run `SUDO` on the make commands below if you get a Permission Denied error.

`./bootstrap`

`./configure --enable-ooxml`

`make`

`make check` 

`make install`
