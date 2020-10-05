#!/usr/bin/python3
import argparse
import zip7


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

if __name__ == "__main__":
    main()