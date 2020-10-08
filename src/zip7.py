from zip7helpers import *
import struct

'''
    TODO List:
    
    1. Implement CRC + Develop other files (7zsteg & parse7z)

'''

class Zip7(object):
    # Constants related to the file format
    MAGIC = b'7z\xBC\xAF\x27\x1C'
    ACCEPTED_ENCODINGS = {
        0x30101: 'LZMA',
        0x21: 'LZMA2'
    }
    HEADER_LEN = 0x20

    ## Predefining some object types for the IDE
    data = bytes()

    # Constructor
    def __init__(self, file_name, ignore_magic=False):
        # Open file and grab data
        with open(file_name, 'rb') as z:
            self.data = z.read()

        # Verify the file is 7zip
        test_magic = self.data[:len(self.MAGIC)]
        if not ignore_magic:
            if test_magic != self.MAGIC:
                raise Zip7FileException('Not a 7zip file.')

        # Initialize dataclass objects
        self.header = Header()
        self.header.magic = test_magic
        self.footer = Footer()
        self.body = Body()
        self.steg = Steg()

        # Perform various data parsing to populate the class information
        self.parse_header()
        self.parse_footer()
        self.parse_body()
        self.parse_steg()

    ## Parsing the various parts of the file to <think of word later, propoagat einfo basically>
    def parse_header(self):
        # Extract information about the file and footer from the header
        self.header.data = data = self.data[:self.HEADER_LEN]
        self.header.version = struct.unpack('>H', data[0x6:0x8])[0]
        self.header.header_crc = struct.unpack('>I', data[0x8:0xC])[0]
        # The following footer information comes FROM the header
        self.header.footer_start = self.HEADER_LEN + struct.unpack('<Q', data[0xC:0x14])[0]
        self.header.footer_length = struct.unpack('<Q', data[0x14:0x1C])[0]
        self.header.footer_crc = struct.unpack('>I', data[0x1C:self.HEADER_LEN])[0]

    def parse_footer(self):
        self.footer.data = self.data[self.header.footer_start:self.header.footer_start + self.header.footer_length]
        self.footer.stream = Zip7ByteStream(self.footer.data)
        while not self.footer.stream.eof():
            opcode = self.footer.stream.read_int()
            #print('%02x' % opcode)
            self.footer_process(opcode)

    # Process the footer opcodes
    def footer_process(self, opcode):
        if len(self.footer.expected):
            if opcode not in self.footer.expected:
                raise Zip7UnknownException('Invalid opcode pattern (%02x came after %02x).' % (opcode, self.footer.stream._stream[self.footer.stream._cursor-2]))

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
        # FilesInfo
        if opcode == 0x05: # Get file data when it's available within the footer
            self.footer.num_files = self.footer.stream.read_number()
            self.footer.expected = [0x0E, 0x0F, 0x19]
            return
        # PackInfo
        if opcode == 0x06: # The second byte following 0x17 - PackedHeader
            self.footer.data_offset = self.footer.stream.read_number()
            # Read more bytes to determine how many streams there are
            self.footer.stream_count = self.footer.stream.read_int()
            self.footer.expected = [0x09]
            return
        # UnpackInfo
        if opcode == 0x07:
            self.footer.expected = [0x0B] # Folder
            return
        # kSize
        if opcode == 0x09:
            for i in range(self.footer.stream_count):
                self.footer.pack_size.append(self.footer.stream.read_number())
            self.footer.expected = [0x00]
            return
        # UnpackDigest/CRC
        if opcode == 0x0A:
            crc_bool = self.footer.stream.read_int()
            if not crc_bool:
                raise Zip7UnimplementedException('CRC Boolean is false, not implemented.')

            self.body.crc = self.footer.stream.read(4)
            self.footer.expected = [0x00]
            return
        # Folder
        if opcode == 0x0B:
            self.footer.folders = self.footer.stream.read_int()
            # Determine if the folder is external
            external = self.footer.stream.read_bool()
            if external:
                raise Zip7UnimplementedException("External folders are not implemented.")
            else:
                # Get the number of encoders
                self.footer.num_encoders = self.footer.stream.read_number()

            # Iterate through the encoders for their information
            self.footer.encoders = list()
            for i in range(self.footer.num_encoders):
                # Create the encoder dictionary and append it to the encoders
                enc = Encoder()
                self.footer.encoders.append(enc)

                # Get the encoder flag and then break apart its bitmask properties
                enc.flag = self.footer.stream.read_int()
                enc.flag_size = enc.flag & 0b00001111
                enc.flag_complex = enc.flag & 0b00010000
                enc.flag_attributes = enc.flag & 0b00100000
                enc.flag_reserved = enc.flag & 0b11000000

                # Get the number of encodings used
                if enc.flag_complex:
                    raise Zip7UnimplementedException('Complex encoders are not implemented.')

                # Get the encoder
                padding = 4 - enc.flag_size
                enc.encoding_id = self.footer.stream.read_int(enc.flag_size, endian='big')

                if enc.encoding_id not in self.ACCEPTED_ENCODINGS.keys():
                    raise Zip7UnimplementedException('Only LZMA & LZMA2 compression supported.')
                enc.encoding = self.ACCEPTED_ENCODINGS[enc.encoding_id]

                # TODO: Maybe. NumInStreams/NumOutStreams are for Complex Codecs only - Skipping
                # Address attributes/properties
                if enc.flag_attributes:
                    enc.properties_count = self.footer.stream.read_number()
                    enc.properties = self.footer.stream.read(enc.properties_count) # "Dangerous" but no real harm

            # Next up: either CoderUnpackSize, UnpackDigest, or END
            self.footer.expected = [0x0C, 0x0A, 0x00]
            return
        # EncoderUnpackSize
        if opcode == 0x0C:
            self.footer.encoder_unpack_size = self.footer.stream.read_number()
            # TODO: Strangely, I've found 7z's that have extra data here until 0x0A? But 0x0A is optional
            # No GOOD fix really addresses it. For now, just skip them until getting to 0x0A
            # If anyone knows anything about this, please let me know!
            while self.footer.stream.read_int() != 0x0A:
                if self.footer.stream.eof():
                    raise Zip7UnknownException('Files without UnpackDigest CRCs not supported due to weird bug.')

            return self.footer_process(0x0A)
        # FileName
        if opcode == 0x11:
            # Get the length of the file's name
            name_len = self.footer.stream.read_number()
            external = self.footer.stream.read_bool()
            if external:
                raise Zip7UnimplementedException('External FileName Streams are not implemented.')

            self.footer.file_name = self.footer.stream.read(name_len - 1).decode('utf-16')
            self.expected = [0x00, 0x14, 0x19]
            return
        # MTime
        if opcode == 0x14:
            # Get the length of MTime
            mtime_size = self.footer.stream.read_number()
            external = self.footer.stream.read_bool()
            if external:
                self.footer.mtime_info = self.footer.stream.read(mtime_size-1)
            else:
                raise Zip7UnimplementedException('Internal MTime values not implemented.')

            self.footer.expected = [0x12, 0x13, 0x15]
            return
        # Attributes
        if opcode == 0x15:
            # Get attribute length
            attribute_size = self.footer.stream.read_number()
            external = self.footer.stream.read_bool()
            if external:
                self.footer.attribute_info = self.footer.stream.read(attribute_size-1)
            else:
                raise Zip7UnimplementedException('Internal Attribute values not implemented.')

            self.footer.expected = [0x00]
            return
        # EncodedHeader
        if opcode == 0x17:
            self.footer.type = "Packed"
            self.footer.expected = [0x06]
            return
        # "Dummy" AKA nop
        if opcode == 0x19:
            nop_count = self.footer.stream.read_number()
            for i in range(nop_count):
                test_data = self.footer.stream.read_int()
                if test_data != 0x00:
                    raise Zip7FileException('Data found which should have been 0x00s for nopping: %02x' % test_data)
            # Perhaps I should have expected follow-ups here, but I don't know where all nop can go
            return

        # Many opcodes aren't usually in 7zip, and so are not implemented here
        if opcode in self.UNIMPLEMENTED:
            raise Zip7UnknownException('Opcode %02x not implemented or maybe invalid.' % opcode)


    def parse_body(self):
        self.body.length = self.footer.data_offset + sum(self.footer.pack_size)
        self.body.data = self.data[0x20: 0x20 + self.body.length]

    def parse_steg(self):
        self.steg.center_start = self.HEADER_LEN + self.body.length
        self.steg.center_length = self.header.footer_start - self.steg.center_start
        self.steg.center_data = self.data[self.steg.center_start: self.steg.center_start + self.steg.center_length]
        self.steg.bottom_start = self.header.footer_start + self.header.footer_length
        self.steg.bottom_length = len(self.data) - self.steg.bottom_start
        self.steg.bottom_data = self.data[self.steg.bottom_start: self.steg.bottom_start + self.steg.bottom_length]