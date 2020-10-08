#!/usr/bin/python3
import argparse
import zip7

DIVIDER = '================================'
PRINT_HEADER = """------- Header Properties ------
Magic - - - - - - {magic}
Version - - - - - {version}
Header CRC- - - - {header_crc:x}
Footer Start- - - 0x{footer_start:x}
Footer Length - - 0x{footer_length:x}
Footer CRC- - - - {footer_crc}"""
PRINT_FOOTER = """------- Footer Properties ------
Data Offset - - - 0x{data_offset:x}
Pack Size(s)- - - {pack_sizes}
Compression - - - {compression}"""
PRINT_BODY = """-------- Body Properties -------
Body Length - - - 0x{length:x}"""
PRINT_STEG ="""-------- Steg Properties -------
Center Start- - - 0x{center_start:x}
Center Length - - 0x{center_length:x}
Center Data - - - {center_data}
Bottom Start- - - 0x{bottom_start:x}
Bottom Length - - 0x{bottom_length:x}
Bottom Data - - - {bottom_data}"""

def main():
    # Set up argparse
    parser = argparse.ArgumentParser(description='Retrieves file metadata for 7z files.')
    parser.add_argument('file', metavar='FILENAME', type=str, help='7zip file for parsing')
    parser.add_argument('-H', default=False, action='store_true', help='Show only header')
    parser.add_argument('-F', default=False, action='store_true', help='Show only footer')
    parser.add_argument('-P', default=False, action='store_true', help='Show only packed data')
    parser.add_argument('-S', default=False, action='store_true', help='Show only steg information')

    # Use argparse for... arg parsing
    args = vars(parser.parse_args())
    file_name = args['file']

    # Open the file into the 7zip file class
    try:
        file = zip7.Zip7(file_name)
    except FileNotFoundError:
        print("File not found. QUITTING")
        return 1

    ## Print out all of the relevant parsed information
    # Print out header information
    print(DIVIDER)
    header_data = {
        "magic": ''.join(str(file.header.magic).split('"')[1:-1]),
        "version": file.header.version,
        "header_crc": file.header.header_crc,
        "footer_start": file.header.footer_start,
        "footer_length": file.header.footer_length,
        "footer_crc": file.header.footer_crc
    }
    print(PRINT_HEADER.format(**header_data))
    # Print out footer information
    print(DIVIDER)
    footer_data = {
        'data_offset': file.footer.data_offset,
        'pack_sizes': str(['0x%x'%size for size in file.footer.pack_size]).replace("'",''),
        'compression': file.footer.encoders[0].encoding
    }
    print(PRINT_FOOTER.format(**footer_data))
    # Print out body information
    print(DIVIDER)
    body_data = {
        'length': file.body.length
    }
    print(PRINT_BODY.format(**body_data))
    # Print out steg information
    print(DIVIDER)
    steg_data = {
        'center_start': file.steg.center_start,
        'center_length': file.steg.center_length,
        'center_data': file.steg.center_data,
        'bottom_start': file.steg.bottom_start,
        'bottom_length': file.steg.bottom_length,
        'bottom_data': file.steg.bottom_data,
    }
    print(PRINT_STEG.format(**steg_data))
    print(DIVIDER)


if __name__ == "__main__":
    main()