#!/usr/bin/python3
import argparse
import os
import zip7
import re, fnmatch
from natsort import natsorted
import sys

"""
For injecting or extracting steganographic data from 7z files.
"""

BASE_FILE_PATTERN = '^{prompt}\\.7z$'

def main():
    # Set up argparse
    parser = argparse.ArgumentParser(description='Allows for the injection or extraction of steganographic data from 7z files.')
    parser.add_argument('file_pattern', metavar='PATTERN', type=str, help='pattern for files (?/* are wildcards); if more than one file is matched, the steganographic data will be striped across all matching files in alphabetical order')
    parser.add_argument('-r', action='store_true', dest='regex', help='use regular expression for matching patterns')
    parser.add_argument('-c/-b', action='store_true', help='steganographic data location; DEFAULT center (-c) or bottom (-b)')
    parser.add_argument('-c', action='store_true', default=True, dest='center', help=argparse.SUPPRESS)
    parser.add_argument('-b', action='store_false', dest='center', help=argparse.SUPPRESS)
    parser.add_argument('-d', metavar='DATA_FILE', help='if provided, data from DATA_FILE will be injected; otherwise, the script will extract')

    # Use argparse for... arg parsing
    args = vars(parser.parse_args())
    file_pattern = args['file_pattern']
    data_file = args['d']
    center = args['center']
    use_regex = args['regex']

    path = os.path.abspath(file_pattern)
    folder, file_pattern = get_path_info(path)

    all_files = os.listdir(folder)
    matching_files = list()

    if use_regex:
        file_pattern = BASE_FILE_PATTERN.format(prompt=file_pattern)
        for file in all_files:
            if re.match(file_pattern, file):
                matching_files.append(file)
    else:
        matching_files = fnmatch.filter(all_files, file_pattern)

    if len(matching_files) == 0:
        print('No files match pattern. QUITTING!')
        return 1

    # Prepend the folder back on, for sorting
    for i, file in enumerate(matching_files):
        matching_files[i] = folder + file

    # Natsort them (i.e., 1 -> 2 -> 10, not 1 -> 10 -> 2)
    files = natsorted(matching_files)

    if data_file:
        try:
            with open(data_file, 'rb') as f:
                data = f.read()
        except FileNotFoundError:
            print('Data file not found. QUITTING!')
            return 1

        inject_files(files, data, center)
    else:
        extracted = extract_files(files, center)
        # Write the bytes directly instead of printing and dealing with codecs
        sys.stdout.buffer.write(extracted)

def inject_files(files, all_data, center):
    file_count = len(files)
    chunks = create_chunks(all_data, file_count)
    zips = list()
    for file, data in zip(files, chunks):
        z = zip7.Zip7(file)
        zips.append(z)
        inject(z, data, center)

    # The reason to separate these is for batching: decrease odds of a partial-injection due to an error in later files
    for file in zips:
        file.save(file_overwrite=True, update_crcs=True)

# For dividing up data ~equally among large chunks
def create_chunks(data, i):
    if i == 0:
        return []

    split_pos = int(len(data) * 1/i)
    return [data[:split_pos]] + create_chunks(data[split_pos:], i-1)

def inject(file, data, center):
    if center:
        file.steg.center_data = data
        file.header.footer_start += len(data)
    else:
        file.steg.bottom_data = data


def extract_files(files, center):
    count = len(files)
    data = b''
    for i in range(count):
        file = zip7.Zip7(files[i])
        new_data = extract(file, center)
        data += new_data

    return data

def extract(file, center):
    if center:
        return file.steg.center_data
    else:
        return file.steg.bottom_data

def get_path_info(path):
    folder = '\\'.join(path.split('\\')[:-1]) or os.getcwd()
    folder = os.path.abspath(folder) + '\\'
    file_pattern = ''.join(path.split('\\')[-1])
    return folder, file_pattern

if __name__ == "__main__":
    main()
