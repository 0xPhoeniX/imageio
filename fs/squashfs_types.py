from enum import Enum
from math import ceil
from struct import unpack, calcsize
from typing import NamedTuple
from textwrap import dedent


SQUASHFS_MAGIC              = 0x73717368
METADATA_BLOCK_SIZE         = 8 * 1024
IMAGE_BLOCK_SIZE            = None

SuperblockFlags = {
    'UNCOMPRESSED_INODES'     : 0x0001,
    'UNCOMPRESSED_DATA'       : 0x0002,
    'CHECK'                   : 0x0004,
    'UNCOMPRESSED_FRAGMENTS'  : 0x0008,
    'NO_FRAGMENTS'            : 0x0010,
    'ALWAYS_FRAGMENTS'        : 0x0020,
    'DUPLICATES'              : 0x0040,
    'EXPORTABLE'              : 0x0080,
    'UNCOMPRESSED_XATTRS'     : 0x0100,
    'NO_XATTRS'               : 0x0200,
    'COMPRESSOR_OPTIONS'      : 0x0400,
    'UNCOMPRESSED_IDS'        : 0x0800}


class InodeType(Enum):
    BASIC_DIR               = 1
    BASIC_FILE              = 2
    BASIC_SYMLINK           = 3
    BASIC_BLOCK_DEV         = 4
    BASIC_CHAR_DEV          = 5
    BASIC_FIFO              = 6
    BASIC_SOCKET            = 7
    EXTENDED_DIR            = 8
    EXTENDED_FILE           = 9
    EXTENDED_SYMLINK        = 10
    EXTENDED_BLOCK_DEV      = 11
    EXTENDED_CHAR_DEV       = 12
    EXTENDED_FIFO           = 13
    EXTENDED_SOCKET         = 14


class Compression(Enum):
    GZIP                    = 1
    LZMA                    = 2
    LZO                     = 3
    XZ                      = 4
    LZ4                     = 5
    ZSTD                    = 6


class SuperBlock(NamedTuple):
    magic: int
    inode_count: int
    modification_time: int
    block_size: int
    fragment_entry_count: int
    compression_id: Compression
    block_log: int
    flags: int
    id_count: int
    version_major: int
    version_minor: int
    root_inode_ref: int
    bytes_used: int
    id_table_start: int
    xattr_id_table_start: int
    inode_table_start: int
    directory_table_start: int
    fragment_table_start: int
    export_table_start: int

    @classmethod
    def unpack(cls, fd, endianess):
        global IMAGE_BLOCK_SIZE
        f = endianess + "5I6H8Q"
        s = calcsize(f)
        r = unpack(f, fd.read(s))
        IMAGE_BLOCK_SIZE = r[3]
        return cls(r[0], r[1], r[2], r[3], r[4],
                   Compression(r[5]), r[6], r[7], r[8], r[9],
                   r[10], r[11], r[12], r[13], r[14],
                   r[15], r[16], r[17], r[18])


class MetadataBlock(NamedTuple):
    comp: bool
    dlen: int

    @classmethod
    def unpack(cls, fd, endianess):
        f = endianess + "H"
        s = 2
        r = unpack(f, fd.read(s))
        return cls(not ((r[0] & 0x8000) == 0x8000),
                   (r[0] & 0x00007FFF) & 0xFFFFFFFF)


class BasicDirNode(NamedTuple):
    inode_type: int
    permissions: int
    uid: int
    gid: int
    modified_time: int
    inode_number: int

    block_idx: int
    hard_link_count: int
    file_size: int
    block_offset: int
    parent_inode_number: int
    dlen: int

    @classmethod
    def unpack(cls, data, endianess, idTable):
        f = endianess + "4HIIIIHHI"
        s = calcsize(f)
        r = unpack(f, data[:s])
        return cls(r[0], r[1], idTable[r[2]], idTable[r[3]], r[4], r[5],
                   r[6], r[7], r[8], r[9], r[10], s)


class DirectoryIndex(NamedTuple):
    index: int
    start: int
    name_size: int
    name: str
    dlen: int

    @classmethod
    def unpack(cls, data, endianess):
        f = endianess + "3I"
        s = calcsize(f)
        r = unpack(f, data[:s])
        name = data[s: (s + r[2] + 1)].decode('utf-8')
        s = s + r[2] + 1
        return cls(r[0], r[1], r[2], name, s)


class ExtendedDirNode(NamedTuple):
    inode_type: int
    permissions: int
    uid: int
    gid: int
    modified_time: int
    inode_number: int

    hard_link_count: int
    file_size: int
    block_idx: int
    parent_inode_number: int
    index_count: int
    block_offset: int
    xattr_idx: int
    index: list
    dlen: int

    @classmethod
    def unpack(cls, data, endianess, idTable):
        f = endianess + "4H2I4I2HI"
        s = calcsize(f)
        r = unpack(f, data[:s])
        offset = 0
        index = []
        for i in range(0, r[10]):
            idx = DirectoryIndex.unpack(data[s + offset:], endianess)
            index.append(idx)
            offset = offset + idx.dlen
        return cls(r[0], r[1], idTable[r[2]], idTable[r[3]], r[4], r[5],
                   r[6], r[7], r[8], r[9], r[10], r[11], r[12],
                   index, s + offset)


class BasicFileNode(NamedTuple):
    inode_type: int
    permissions: int
    uid: int
    gid: int
    modified_time: int
    inode_number: int

    blocks_start: int
    fragment_block_index: int
    block_offset: int
    file_size: int
    block_sizes: list
    dlen: int

    @classmethod
    def unpack(cls, data, endianess, idTable):
        f = endianess + "4H2I4I"
        s = calcsize(f)
        r = unpack(f, data[:s])

        if r[7] == 0xFFFFFFFF:
            blk_sizes_len = int(ceil(r[9] * 1.0 / IMAGE_BLOCK_SIZE))
        else:
            blk_sizes_len = int(r[9] * 1.0 / IMAGE_BLOCK_SIZE)

        block_sizes = []
        if blk_sizes_len > 0:
            block_sizes = list(unpack(endianess + "%dI" % blk_sizes_len,
                                      data[s: s + 4 * blk_sizes_len]))
        return cls(r[0], r[1], idTable[r[2]], idTable[r[3]], r[4], r[5],
                   r[6], r[7], r[8], r[9], block_sizes, s + blk_sizes_len * 4)


class ExtendedFileNode(NamedTuple):
    inode_type: int
    permissions: int
    uid: int
    gid: int
    modified_time: int
    inode_number: int

    blocks_start: int
    file_size: int
    sparse: int
    hard_link_count: int
    fragment_block_index: int
    block_offset: int
    xattr_idx: int
    block_sizes: int
    dlen: int

    @classmethod
    def unpack(cls, data, endianess, idTable):
        f = endianess + "4H2I3Q4I"
        s = calcsize(f)
        r = unpack(f, data[:s])

        if r[10] == 0xFFFFFFFF:
            block_sizes_len = int(ceil(r[7] / IMAGE_BLOCK_SIZE * 1.0))
        else:
            block_sizes_len = int(r[7] / IMAGE_BLOCK_SIZE)

        block_sizes = []
        if block_sizes_len > 0:
            block_sizes = list(unpack(endianess + "%dI" % block_sizes_len,
                                      data[s: s + 4 * block_sizes_len]))
        return cls(r[0], r[1], idTable[r[2]], idTable[r[3]], r[4], r[5],
                   r[6], r[7], r[8], r[9], r[10], r[11], r[12], block_sizes,
                   s + 4 * block_sizes_len)


class BasicSymlinkNode(NamedTuple):
    inode_type: int
    permissions: int
    uid: int
    gid: int
    modified_time: int
    inode_number: int

    hard_link_count: int
    target_size: int
    target_path: str
    dlen: int

    @classmethod
    def unpack(cls, data, endianess, idTable):
        f = endianess + "4H2III"
        s = calcsize(f)
        r = unpack(f, data[:s])
        target_path = data[s: (s + r[7])].decode('utf-8')
        return cls(r[0], r[1], idTable[r[2]], idTable[r[3]], r[4], r[5],
                   r[6], r[7], target_path, s + r[7])


class ExtendedSymlinkNode(NamedTuple):
    @classmethod
    def unpack(cls, data, endianess, idTable):
        raise NotImplementedError


class BasicDeviceNode(NamedTuple):
    inode_type: int
    permissions: int
    uid: int
    gid: int
    modified_time: int
    inode_number: int

    hard_link_count: int
    device: int
    dlen: int

    @classmethod
    def unpack(cls, data, endianess, idTable):
        f = endianess + "4H2I2I"
        s = calcsize(f)
        r = unpack(f, data[:s])
        return cls(r[0], r[1], idTable[r[2]], idTable[r[3]], r[4], r[5],
                   r[6], r[7], s)


class ExtendedDeviceNode(NamedTuple):
    @classmethod
    def unpack(cls, data, endianess, idTable):
        raise NotImplementedError


class BasicIPCNode(NamedTuple):
    @classmethod
    def unpack(cls, data, endianess, idTable):
        raise NotImplementedError


class ExtendedIPCNode(NamedTuple):
    @classmethod
    def unpack(cls, data, endianess, idTable):
        raise NotImplementedError


node_index = [None,
              BasicDirNode,
              BasicFileNode,
              BasicSymlinkNode,
              BasicDeviceNode,
              BasicDeviceNode,
              BasicIPCNode,
              BasicIPCNode,
              ExtendedDirNode,
              ExtendedFileNode,
              ExtendedSymlinkNode,
              ExtendedDeviceNode,
              ExtendedDeviceNode,
              ExtendedIPCNode,
              ExtendedIPCNode]


class DirectoryHeader(NamedTuple):
    count: int
    start: int
    node_number: int
    dlen: int

    @classmethod
    def unpack(cls, data, endianess):
        f = endianess + "IIi"
        s = calcsize(f)
        r = unpack(f, data[:s])
        return cls(r[0], r[1], r[2], s)


class DirectoryEntry(NamedTuple):
    offset: int
    inode_offset: int
    type: int
    name_size: int
    name: str
    dlen: int

    @classmethod
    def unpack(cls, data, endianess):
        f = endianess + "HhHH"
        s = calcsize(f)
        r = unpack(f, data[:s])
        name = data[s: (s + r[3] + 1)].decode('utf-8')
        return cls(r[0], r[1], r[2], r[3], name, s + r[3] + 1)


class FragmentBlockEntry(NamedTuple):
    start: int
    size: int
    unused: int
    comp: bool
    dlen: int

    @classmethod
    def unpack(cls, data, endianess):
        f = endianess + "QII"
        s = calcsize(f)
        r = unpack(f, data[:s])
        comp = not ((r[1] & 0x1000000) == 0x1000000)
        size = (r[1] & 0xffffff) & 0xFFFFFFFF
        return cls(r[0], size, r[2], comp, s)
