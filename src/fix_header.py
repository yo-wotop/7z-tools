#!/usr/bin/python3
import argparse
import zip7
import struct

"""
For fixing broken headers (i.e., primarily CRCs)
Also intended as a primer to see how to make a script using the zip7 core library
"""

def main():
    # Set up argparse
    parser = argparse.ArgumentParser(description='Fixes header metadata for 7z files.')
    parser.add_argument('file', metavar='FILENAME', type=str, help='7zip file that needs to be fixed')
    parser.add_argument('-o', '--out-file', default='out.7z', help='Output file name for fixed 7z file')

    # Use argparse for... arg parsing
    args = vars(parser.parse_args())
    file_name = args['file']
    out_file = args['out_file']

    # Open the file into the 7zip file class
    try:
        file = zip7.Zip7(file_name)
    except FileNotFoundError:
        print("File not found. QUITTING")
        return 1

    # Recreate the header from scratch
    file.header.magic = file.MAGIC
    file.header.version = 4
    file.header.footer_start = file.header.footer_start - file.HEADER_LEN
    file.header.footer_length = file.header.footer_length

    # Save the file
    file.update_header()
    file.save(file_name=out_file, update_crcs=True)
    print('Fixed file output saved to: %s' % out_file)




if __name__ == "__main__":
    main()