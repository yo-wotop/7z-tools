# 7z-tools

Python tools made for the general quick extraction of relevant data from 7zip files, particularly with a focus on CTF challenges and steganography.

## Features

Comes with the following functionality:

* Core: Zip7 Class
  * Useful for custom script parsing of files
* Script: parse7z.py
  * Run against a target file to view variety of file metadata (see example below)
* Script: fix_header.py
  * Fixes corrupt 7z files that are properly constructed but have broken headers:
    * Invalid magic bytes
    * Incorrect CRCs
  * Note: These fixes are intended to fix *intentional* 7zip destructions, such as challenges in CTFs or when you are trying to inject steganography or random stuff and need to fix the CRCs. It cannot restore 7zip files that have been truncated or corrupted and have lost data.
* Script: 7zsteg.py
  * Allows for the injection or extraction of steganographic data from 7zips, either from between the body and footer sections or after the bottom of the file.
  * One file may be specified (for injection or extraction), or the injection/extraction may be striped across many files.

## Contributions

Since 7zip is has a rather exhaustive protocol, much of the functionality (and non-LZMA* compression algorithms) was not implemented. Anything unimplemented has been explicitly marked to raise a `Zip7UnimplementedException` with a detailed description. Implementations of these features are very welcome.

Please follow the standing formatting, which are *generally* PEP8-esque. Use `lowercase_snake_case` for variables and functions, `UPPERCASE_SNAKE_CASE` for constants, and `PascalCase` for class defintions. Note that deviations from the formatting will increase the time for any potential pull requests.

## Installation

Python 3.7+ is required in order to use dataclasses. Additional modules may be added through pip:   

```
pip install -r requirements.txt
```

## Usage

#### parse7z.py

Switches may be specified to show only certain information (e.g., `-S` will only print steganography information).

```
$ ./parse7z.py --help
usage: parse7z.py [-h] [-H] [-F] [-B] [-S] FILENAME

Retrieves file metadata for 7z files.

positional arguments:
  FILENAME    7zip file for parsing

optional arguments:
  -h, --help  show this help message and exit
  -H          Show only header information
  -F          Show only footer information
  -B          Show only body information
  -S          Show only steg information
```

If no switches are specified, all default output will be included:

```
$ ./parse7z.py sample_with_png_stego.7z
=====================================
--------- Header Properties ---------
Magic - - - - - - - - 7z\xbc\xaf'\x1c
Version - - - - - - - 4
Header CRC- - - - - - 0xe724e83c
Header CRC Valid? - - True
Footer Start- - - - - 0x211
Footer Length - - - - 0x23
Footer CRC- - - - - - 0xdc4c6b47
Footer CRC Valid? - - True
=====================================
--------- Footer Properties ---------
Data Offset - - - - - 0x160
Pack Size(s)- - - - - [0x80]
Compression - - - - - LZMA
=====================================
---------- Body Properties ----------
Body Length - - - - - 0x1e0
=====================================
---------- Steg Properties ----------
Center Start- - - - - 0x200
Center Length - - - - 0x11
Center Data - - - - - b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00'
Bottom Start- - - - - 0x234
Bottom Length - - - - 0x0
Bottom Data - - - - - b''
=====================================
```

#### fix_header.py

Run it against a target 7zip file and it will correct the magic header, version information, and CRCs. Useful primarily as an example for working with the `Zip7` library or for just messing around with 7z files. By specifying an optional outfile (`-o`), the script will output the fixed 7z file without editing the original.

```
./fix_header.py --help
usage: fix_header.py [-h] [-o OUT_FILE] FILENAME

Fixes header metadata for 7z files.

positional arguments:
  FILENAME              7zip file that needs to be fixed

optional arguments:
  -h, --help            show this help message and exit
  -o OUT_FILE, --out-file OUT_FILE
                        Output file name for fixed 7z file

```

#### 7zsteg.py

This tool may be used to arbitrarily extract steganographic data from or inject data into 7z files.

```
./7zsteg.py --help
usage: 7zsteg.py [-h] [-r] [-c/-b] [-d DATA_FILE] PATTERN

Allows for the injection or extraction of steganographic data from 7z files.

positional arguments:
  PATTERN       pattern for files (?/* are wildcards); if more than one file is matched, the steganographic data will be striped across all matching files in alphabetical order

optional arguments:
  -h, --help    show this help message and exit
  -r            use regular expression for matching patterns
  -c/-b         steganographic data location; DEFAULT center (-c) or bottom (-b)
  -d DATA_FILE  if provided, data from DATA_FILE will be injected; otherwise, the script will extract
```

The required argument `PATTERN` is, by default, an `fnmatch`-style pattern used to match the targeted 7z file(s). An exact name may be provided if one wishes to extract/inject with a single file, or a pattern matching many files (such as `sample_*.7z`) may be provided. If the pattern matches more than one file, the data will be injected striped across all files (alphabetically) that it matches. If extraction is specified, data will be extracted (striped) from all files before being concatenated in `stdout`.  

The `-r` switch may be used instead to match `PATTERN` as a Regular Expression. Please note that all Regular Expression matches are in the form of `^{input}\.7z$`.  

In addition, the `-c` and `-b` switches dictate the position of where the steganographic data will be read from or written to. This script primarily acknowledges two locations to hide steganographic data: the center (between the packed body and the footer) and the bottom (below the footer). By default, the center (`-c`) is selected. Only one may be used at a time, although any file may have data in both locations.

##### Injection

To inject data, the `-d` option **must** be specified. This points to a valid file containing the data that you wish to inject into the 7z archive(s).

For example, if you wish to inject a cat picture (`cat.png`), within the bottom area (`-b`), striped across ALL files like `sample_#.7z`, the following payload may be used:  

```
./7zsteg.py -d cat.png -b sample_*.7z
```

##### Extraction

In order to extract data, simply do not specify the `-d` option. For example, if you wish to extract the PNG file into from the *Injection* section, using a Regular Expression, into `test.png`, it may be done as follows:

```
./7zsteg.py -b -r sample_\\d+ > test.png
```  


#### Zip7 Core

The Zip7 core file may be used to create custom scripts to parse 7zip files. More information is parsed than is displayed by the `parse7z.py` script, and more may be implemented internally by adding new features in lieu of the current `Zip7UnimplementedException` handlers.

Parsing data from 7zip files with the core library is easy:

```
$ python
...
>>> import zip7
>>> file = zip7.Zip7('sample.7z')
>>> file.header
Header(magic=b"7z\xbc\xaf'\x1c", version=4, header_crc=1021846759, footer_start=529, footer_length=35, footer_crc=1198214364, data=b"7z\xbc\xaf'\x1c\x00\x04<\xe8$\xe7\xf1\x01\x00\x00\x00\x00\x00\x00#\x00\x00\x00\x00\x00\x00\x00GkL\xdc")
>>> file.footer
Footer(stream=<zip7bytestream.Zip7ByteStream object at 0x0000024B7FFC04C0>, expected=[], pack_size=[128], encoders=[Encoder(flag=35, flag_size=3, flag_complex=0, flag_attributes=32, flag_reserved=0, encoding_id=196865, encoding='LZMA', property_count=0, properties=b']\x00\x10\x00\x00')], data=b'\x17\x06\x81`\x01\t\x80\x80\x00\x07\x0b\x01\x00\x01#\x03\x01\x01\x05]\x00\x10\x00\x00\x0c\x80\xd6\n\x01i\x13,\x7f\x00\x00', type='Packed', folders=1, num_encoders=1, encoder_unpack_size=214, stream_count=1, data_offset=352)
>>> file.body
Body(length=480, data=b'\x01\x01[r\x8b\xa7S\x16\x9f\xc7AV$p{t\xde2P\xdb\xd4C\x92u\x8d\x16\x1e\xec_mK{\x06S"\xb3\xcfMq\xb5C\xbdr\x83\x957^F\'\xfa\x92@\xa3k\xca\xb1%\x13b\xb9\xe8\x86S\xe2\xf6\xd1\x14\x83Hv\x0f\xb3\x19oz\xa7O*\xd5\xce>\xf3d\xd0]\xda\xf5w7\x9b\xf8\xcbB]\x11Z\xb5\xbf\xdb\x84.\x08!\x84\x98\x81\xee\xc2\x1f|@I\x1b\x8a\xb1K\xf2>h\x9dh\x03z\x0b\xec\xfc\xc4TE\xfdX"`\xa0\xfe\xbbI\xf0\xbcw\xe3A<s\xdc\\\xec\x98\xae}x\x8a&\xaf\r\xb8\xe5\xc0\x15M\x08\xa6!&\xc7\x93\t\xd8\x1d\xa2\x04\x0c\xc6U\x00\xcaz\xb7W\xd0$q\xfa\xa3\x06\x95\xafI\xf4\x1d\xdcT\x9bC-\xb61\xfe2\xb4PG\xb6\x84\xcf\xd3\xc3\xe1\xe6\x17\xe4\x120\x02*\x1c0"\x84.\xced\x9f2\xe7n\xe8-p\x85m\x17\x9e\xc1\xa2\x86\xa3\x89\x80Y\x05\xc2\xf3\x8d\xf0~U\xed6sdG\xab\xd4\xd7\xa1o\xd7\x11\xc8Uz\x88=\xfa\xef\xf5\x81\x1e\xeb\xcd\xd1\xd1|L\x88\xd97\xa1y\xe4(I/6!#R\x9a\x97\xceh\xd0M!\x08\xad\xdbY\xa2g\xd9^\x92^\xfa1\xa8\xe0\xc5\x84\x1dTD\x1f\xb2\x8be3N\x99\xba\x89&\xe2\xe9C\x9f22\xf8\x16H\x92\x92\xccVZ\xaaT\xa8\xab\x1b\xb3\r\xab\x9d\xfc@\xbd\x80\x00\x00\x00\x813\x07\xae\x0f\xd59\xf2i\x17$\xd3\xfe\xb3p\x18\x81@\x1eD\xe7W{\xc7(Lr4\xc8l\x1a\xb3\xd4\x07\xf0QK\x0c\xe8\xe4\xa0"\xa6CO@\x97\x96?\xcb\xa3\xde\xeeO\x7f\xb2\xf8E\x9c8\xd0g\x02L\x96\xba\xb5\xf3{j5\xe7\xc0\xc0Y\xaf\x94\xdb\xe0\x87\x1b\xa4\x14O\x0c\xe3\xfc\x12\xef\xa4\xc5\tZ\xa5\xea.\xd5\xe4\x02\xc1\x04\x1c0V\xae\x14\x01=;%n\xb3\xb1\'\x0e\xc2\x99\x7f\r\x8e\x90\xba(#\x11\x00')
>>> file.steg
Steg(center_start=512, center_length=17, center_data=b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00', bottom_start=564, bottom_length=0, bottom_data=b'')
```

For example, plaintext file names included in the footers of LZMA2-compressed files may be trivially extracted. See below:

```
$ python
...
>>> import zip7
>>> file = zip7.Zip7('sample2.7z')
>>> file.footer.file_name
'sample_text_file.txt'
```

## Acknowledgements

Special thanks to [Hiroshi Miura](https://github.com/miurahr), author of the [py7zr](https://github.com/miurahr/py7zr) package and the [only legible 7z file structure documentation on the internet](https://py7zr.readthedocs.io/en/stable/archive_format.html). This would have taken an extra few months without you.

