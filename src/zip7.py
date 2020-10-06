from dataclasses import dataclass, field
from typing import List
from pwn import u8, u16, u32, u64, p8
from zip7bytestream import Zip7ByteStream

class Zip7(object):
    # Constants related to the file format
    MAGIC = b'7z\xBC\xAF\x27\x1C'
    LZMA_ENCODING = 0x30101
    HEADER_LEN = 0x20
    UNIMPLEMENTED = [
        0x02, 0x03, 0x04, 0x05,
        0x08, 0x0A, 0x0C, 0x0D,
        0x0E, 0x0F, 0x10, 0x11,
        0x12, 0x13, 0x14, 0x15,
        0x16, 0x18, 0x19
    ]

    ## Predefining some object types for the IDE
    data = bytes()
    # As well as data classes, for dot-notation of objects
    @dataclass
    class header:
        data: [bytes]
        version: int
        crc: [bytes]

    @dataclass
    class encoder:
        flag: int
        flag_size: int
        flag_complex: bool
        flag_attributes: bool
        flag_reserved: int
        encoding_id: int
        property_count: int
        properties: [bytes]

    @dataclass
    class footer:
        expected: [int]
        start: int
        length: int
        crc: [bytes]
        data: [bytes]
        stream: Zip7ByteStream
        type: str
        pack_size: [int]
        folders = int
        num_encoders: int
        encoders: [object]
        encoder_unpack_size: int
        stream_count: int = 1
        data_offset: int = 0

    footer.expected = list()
    footer.pack_size = list()
    footer.encoders = list()

    @dataclass
    class packed:
        data: [bytes]

    @dataclass
    class steg:
        center_data: [bytes]
        end_data: [bytes]

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
        self.parse_header()
        #try:
        self.parse_footer()
        #except:
        #    f = self.footer
        #    print(7,f.folders)

        self.parse_body()
        self.parse_steg()

    ## Parsing the various parts of the file to <think of word later, propoagat einfo basically>
    def parse_header(self):
        # Extract information about the file and footer from the header
        self.header.data = data = self.data[:self.HEADER_LEN]
        self.header.version = u16(data[0x6:0x8], endian='big')
        self.header.crc = data[0x8:0xC]
        # The following footer information comes FROM the header
        self.footer.start = self.HEADER_LEN + u64(data[0xC:0x14])
        self.footer.length = u64(data[0x14:0x1C])
        self.footer.crc = data[0x1C:self.HEADER_LEN]

    def parse_footer(self):
        self.footer.data = self.data[self.footer.start:self.footer.start + self.footer.length]
        self.footer.stream = Zip7ByteStream(self.footer.data)
        while not self.footer.stream.eof():
            opcode = u8(self.footer.stream.read(1))
            print('%02x' % opcode)
            self.footer_process(opcode)

    # Process the footer opcodes
    def footer_process(self, opcode):
        if len(self.footer.expected):
            if opcode not in self.footer.expected:
                raise Zip7Exception('Invalid opcode pattern (%02x came after %02x).' % (opcode, self.footer.stream._stream[self.footer.stream._position-2]))

        self.footer.expected = []
        # kEnd
        if opcode == 0x00: # End the current block
            return
        # Header
        if opcode == 0x01: # Unpacked header section
            self.footer.type = "Unpacked"
            self.footer.expected = [0x04] # MainStreamsInfo
            return
        # MainStreamsInfo
        if opcode == 0x04: # Unpacked header follow-up data
            self.footer.expected = [0x06] # PackInfo
            return
        # PackInfo
        if opcode == 0x06: # The second byte following 0x17 - PackedHeader
            self.footer.data_offset = self.read_number()
            # Read more bytes to determine how many streams there are
            self.footer.stream_count = u8(self.footer.stream.read(1))
            self.footer.expected = [0x09]
            return
        # UnpackInfo
        if opcode == 0x07:
            self.footer.expected = [0x0B] # Folder
            return
        # kSize
        if opcode == 0x09:
            for i in range(self.footer.stream_count):
                self.footer.pack_size.append(self.read_number())
            self.footer.expected = [0x00]
            return
        # UnpackDigest/CRC
        if opcode == 0x0A:
            crc_bool = u8(self.footer.stream.read(1))
            if not crc_bool:
                raise Zip7Exception('CRC Boolean is false, not implemented.')

            self.packed.crc = self.footer.stream.read(4)
            self.footer.expected = [0x00]
            return
        # Folder
        if opcode == 0x0B:
            self.footer.folders = u8(self.footer.stream.read(1))
            # Determine if the folder is "Ext" or not - no idea what this means
            is_ext = u8(self.footer.stream.read(1))
            if is_ext:
                raise Zip7Exception("'Ext' is unimplemented functionality.")
            else:
                # Get the number of encoders
                self.footer.num_encoders = u8(self.footer.stream.read(1))

            # Iterate through the encoders for their information
            for i in range(self.footer.num_encoders):
                # Create the encoder dictionary and append it to the encoders
                enc = self.encoder
                self.footer.encoders.append(enc)

                # Get the encoder flag and then break apart its bitmask properties
                enc.flag = u8(self.footer.stream.read(1))
                enc.flag_size = enc.flag & 0b00001111
                enc.flag_complex = enc.flag & 0b00010000
                enc.flag_attributes = enc.flag & 0b00100000
                enc.flag_reserved = enc.flag & 0b11000000

                # Get the number of encodings used
                if enc.flag_complex:
                    raise Zip7Exception('Cannot handle complex encoders.')

                enc.count = 1 # Otherwise determined by enc.flag_complex
                # Get the encodings
                for i in range(enc.count):
                    enc.encoding_id = u32(b'\x00' + self.footer.stream.read(3), endian='big')

                if enc.encoding_id != self.LZMA_ENCODING:
                    raise Zip7Exception('Only LZMA compression supported.')

                # TODO: Maybe. NumInStreams/NumOutStreams are for Complex Codecs only - Skipping
                # Address attributes/properties
                if enc.flag_attributes:
                    enc.properties_count = self.read_number()
                    enc.properties = self.footer.stream.read(enc.properties_count) # "Dangerous" but no real harm

            # Next up: either CoderUnpackSize, UnpackDigest, or END
            self.footer.expected = [0x0C, 0x0A, 0x00]
            return
        # EncoderUnpackSize
        if opcode == 0x0C:
            self.footer.encoder_unpack_size = self.read_number()
            # Next up: either UnpackDigest or END
            self.footer.expected = [0x0A, 0x00]
            return
        # EncodedHeader
        if opcode == 0x17:
            self.footer.type = "Packed"
            self.footer.expected = [0x06]
            return
        # Many opcodes aren't usually in 7zip, and so are not implemented here
        if opcode in self.UNIMPLEMENTED:
            raise Zip7Exception('Opcode %02x not implemented.' % opcode)

    # Helper function that supports the way that 7zip chooses to store lengths into variable amounts of bytes
    def read_number(self):
        test_byte = u8(self.footer.stream.read(1))
        byte_count = 1 + (test_byte >> 7) # First bit mask indicates whether two bytes are used instead
        if byte_count == 1:
            k_size = test_byte
        elif byte_count == 2:
            size_bytes = p8(test_byte) + self.footer.stream.read(1)
            k_size = u16(size_bytes, endian='big') & 0x7FFF # First bit was the mask

        return k_size



    def parse_body(self):
        pass

    def parse_steg(self):
        pass



class Zip7Exception(Exception):
    pass
