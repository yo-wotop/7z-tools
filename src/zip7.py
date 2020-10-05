from dataclasses import dataclass
from pwn import u16, u32, u64

class Zip7(object):
    # Constants related to the file format
    MAGIC = b'7z\xBC\xAF\x27\x1C'
    HEADER_LEN = 0x20

    ## Predefining some object types for the IDE
    data = bytes()
    # As well as data classes, for dot-notation of objects
    @dataclass
    class header:
        data:           [bytes]
        version:        int
        header_crc:     [bytes]
        footer_start:   int
        footer_len:     int

    @dataclass
    class footer:
        data: [bytes]

    @dataclass
    class packed:
        data: [bytes]

    @dataclass
    class steg:
        data: [bytes]

    # Constructor
    def __init__(self, file_name, ignore_magic=False):
        # Open file and grab data
        with open(file_name, 'rb') as z:
            self.data = z.read()

        # Verify the file is 7zip
        if not ignore_magic:
            if self.data[:len(self.MAGIC)] != self.MAGIC:
                raise Zip7Exception('Not a 7zip file.')

        # Perform various data parsing to populate the class information
        self.parseHeader()
        self.parseFooter()
        self.parsePacked()
        self.parseSteg()

    ## Parsing the various parts of the file to <think of word later, propoagat einfo basically>
    def parseHeader(self):
        # Extract information about the file and footer from the header
        self.header.data = data = self.data[:self.HEADER_LEN]
        self.header.version = u16(data[0x6:0x8], endian='big')
        self.header.header_crc = data[0x8:0xC]
        self.header.footer_start = self.HEADER_LEN + u64(data[0xC:0x14])
        self.header.footer_len = u64(data[0x14:0x1C])
        self.header.footer_crc = data[0x1C:self.HEADER_LEN]

    def parseFooter(self):
        self.footer.data = self.data[self.header.footer_start:self.header.footer_start + self.header.footer_len]


    def parsePacked(self):
        pass

    def parseSteg(self):
        pass



class Zip7Exception(Exception):
    pass
