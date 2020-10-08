from dataclasses import dataclass, field
from zip7bytestream import Zip7ByteStream
from typing import List

## Define data classes for use in the class
@dataclass
class Header:
    magic: [bytes] = b''
    version: int = 0
    header_crc: [bytes] = b''
    header_crc_valid: bool = False
    footer_start: int = 0
    footer_length: int = 0
    footer_crc: [bytes] = b''
    footer_crc_valid: bool = False
    data: [bytes] = b''

@dataclass
class Encoder:
    flag: int = 0
    flag_size: int = 0
    flag_complex: bool = False
    flag_attributes: bool = False
    flag_reserved: int = 0
    encoding_id: int = 0
    encoding: str = ''
    property_count: int = 0
    properties: [bytes] = b''

@dataclass
class Footer:
    stream: Zip7ByteStream = field(default_factory=Zip7ByteStream)
    expected: List[int] = field(default_factory=list)
    pack_size: List[int] = field(default_factory=list)
    encoders: List[Encoder] = field(default_factory=Encoder)
    data: [bytes] = b''
    type: str = ''
    folders: int = 0
    num_encoders: int = 0
    encoder_unpack_size: int = 0
    stream_count: int = 0
    data_offset: int = 0

@dataclass
class Body:
    length: int = 0
    data: [bytes] = b''

@dataclass
class Steg:
    center_start: int = 0
    center_length: int = 0
    center_data: [bytes] = b''
    bottom_start: int = 0
    bottom_length: int = 0
    bottom_data: [bytes] = b''

## Define exceptions for use by the class

class Zip7FileException(Exception):
    # Exceptions that occur because the file is not conforming to the standard
    pass


class Zip7UnimplementedException(Exception):
    # Exceptions that occur because this library was not developed to fully implement every piece of 7z functionality
    pass


class Zip7UnknownException(Exception):
    # Exceptions that occur because of an unknown cause or a misunderstanding of the literature
    pass


