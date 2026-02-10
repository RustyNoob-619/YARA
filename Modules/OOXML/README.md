OOXML YARA module is used to parse OOXML file formats that are typically found in modern documents. The module is based on the PKZIP specification since OOXML files are ZIP archives.

Below are the instructions to install this module in YARA. The module has been tested on YARA 4.5.4. For details on the module usage and functions, please see ooxml.md file here: https://github.com/RustyNoob-619/YARA/blob/main/Modules/OOXML/File%20Structure/docs/modules/ooxml.md

NOTE: The files in the File Structure folder on this repository are arranged based on where they are located in your YARA directory.

Navigate to the File Structure folder and add the following files to their respective locations in your YARA root directory:

ooxml.c: add to yara-4.5.x => libyara => modules => ooxml -> ooxml.c

ooxml.h: add to yara-4.5.x => libyara => include => yara -> ooxml.h

ooxml.md: add to yara-4.5.x => docs => modules -> ooxml.md

After pasting the above files in their respective directories, run the following commands from your YARA root directory:

`./bootstrap`

`./configure --enable-ooxml`

`make`

`make check` 

`make install`
