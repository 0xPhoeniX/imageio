from enum import Enum
from typing import NamedTuple
from struct import unpack, calcsize
import binascii
from fs.compression import *


JFFS2_MAGIC_BITMASK = 0x1985

# /* Compatibility flags. */
JFFS2_COMPAT_MASK = 0xc000
JFFS2_NODE_ACCURATE = 0x2000
JFFS2_FEATURE_INCOMPAT = 0xc000
JFFS2_FEATURE_ROCOMPAT = 0x8000
JFFS2_FEATURE_RWCOMPAT_COPY = 0x4000
JFFS2_FEATURE_RWCOMPAT_DELETE = 0x0000


class InodeType(Enum):
    JFFS2_NODETYPE_DIRENT = JFFS2_FEATURE_INCOMPAT | JFFS2_NODE_ACCURATE | 1
    JFFS2_NODETYPE_INODE = JFFS2_FEATURE_INCOMPAT | JFFS2_NODE_ACCURATE | 2
    JFFS2_NODETYPE_CLEANMARKER = JFFS2_FEATURE_RWCOMPAT_DELETE | JFFS2_NODE_ACCURATE | 3
    JFFS2_NODETYPE_PADDING = JFFS2_FEATURE_RWCOMPAT_DELETE | JFFS2_NODE_ACCURATE | 4
    JFFS2_NODETYPE_SUMMARY = JFFS2_FEATURE_RWCOMPAT_DELETE | JFFS2_NODE_ACCURATE | 6
    JFFS2_NODETYPE_XATTR = JFFS2_FEATURE_INCOMPAT | JFFS2_NODE_ACCURATE | 8
    JFFS2_NODETYPE_XREF = JFFS2_FEATURE_INCOMPAT | JFFS2_NODE_ACCURATE | 9


compressors = [DummyCompressor,
               ZeroCompressor,
               RTimeCompressor,
               Compressor,
               DummyCompressor,
               Compressor,
               ZLibCompressor,
               LZOCompressor,
               LZMACompressor]


def getCompressor(comp_id):
    try:
        return compressors[comp_id]()
    except Exception:
        raise Exception("Unknown compression: %d" % comp_id)


class Compression(Enum):
    NONE = 0
    ZERO = 1
    RTIME = 2
    RUBINMIPS = 3
    COPY = 4
    DYNRUBIN = 5
    ZLIB = 6
    LZO = 7
    LZMA = 8


class FTypes(Enum):
    DT_UNKNOWN = 0
    DT_FIFO = 1
    DT_CHR = 2
    DT_DIR = 4
    DT_BLK = 6
    DT_REG = 8
    DT_LNK = 10
    DT_SOCK = 12
    DT_WHT = 14


def mtd_crc(data):
    return (binascii.crc32(data, -1) ^ -1) & 0xffffffff


class GeneralINode(NamedTuple):
    magic: int
    nodetype: InodeType
    totlen: int
    hdr_crc: int
    hdr_crc_match: bool

    @classmethod
    def unpack(cls, fd, endianess):
        f = endianess + "HHII"
        s = calcsize(f)
        cpos = fd.tell()
        data = fd.read(s)
        r = unpack(f, data)
        return cls(r[0], InodeType(r[1]), r[2], r[3], mtd_crc(data[:-4]) == r[3])


class DirentINode(NamedTuple):
    magic: int
    nodetype: InodeType      # JFFS2_NODETYPE_DIRENT
    totlen: int
    hdr_crc: int
    pino: int                # parent inode
    version: int
    ino: int                 # zero for unlink
    mctime: int
    nsize: int
    dtype: FTypes
    unused: int
    node_crc: int
    name_crc: int
    name: str
    hdr_crc_match: bool
    node_crc_match: bool
    name_crc_match: bool

    @classmethod
    def unpack(cls, fd, endianess):
        f = endianess + "HH6IBBhII"
        s = calcsize(f)
        data = fd.read(s)
        r = unpack(f, data)
        name = fd.read(r[8])
        return cls(r[0], InodeType(r[1]), r[2], r[3], r[4],
                   r[5], r[6], r[7], r[8], FTypes(r[9]),
                   r[10], r[11], r[12], name.decode('utf-8'),
                   mtd_crc(data[:8]) == r[3],
                   True, mtd_crc(name) == r[12])


class RawINode(NamedTuple):
    magic: int      # A constant magic number.
    nodetype: int   # == JFFS2_NODETYPE_INODE
    totlen: int     # Total length of this node (inc data, etc.)
    hdr_crc: int
    ino: int        # Inode number.
    version: int    # Version number.
    mode: int       # The file's type or mode.
    uid: int        # The file's owner.
    gid: int        # The file's group.
    isize: int      # Total resultant size of this inode (used for truncations)
    atime: int      # Last access time.
    mtime: int      # Last modification time.
    ctime: int      # Change time.
    offset: int     # Where to begin to write.
    csize: int      # (Compressed) data size
    dsize: int      # Size of the node's data. (after decompression)
    compr: Compression      # Compression algorithm used
    usercompr: Compression  # Compression algorithm requested by the user
    flags: int      # See JFFS2_INO_FLAG_*
    data_crc: int   # CRC for the (compressed) data.
    node_crc: int   # CRC for the raw inode (excluding data)
    data: bytes
    node_crc_match: bool
    data_crc_match: bool

    @classmethod
    def unpack(cls, fd, endianess):
        f = endianess + "HH5IHH7IBBHII"
        s = calcsize(f)
        data = fd.read(s)
        r = unpack(f, data)
        node_crc_match = mtd_crc(data[:-8]) == r[20]
        if node_crc_match:
            compr = Compression(r[16])
            cnode_data = bytes(fd.read(r[14]))
            data_crc_match = mtd_crc(cnode_data) == r[19]
            node_data = None
            if data_crc_match:
                node_data = getCompressor(compr.value).decompress(cnode_data, r[15])
            return cls(r[0], r[1], r[2], r[3], r[4],
                       r[5], r[6], r[7], r[8], r[9],
                       r[10], r[11], r[12], r[13], r[14],
                       r[15], compr, Compression(r[17]), r[18], r[19],
                       r[20], node_data, node_crc_match,
                       data_crc_match)


NODETYPES = {
    InodeType.JFFS2_NODETYPE_DIRENT: DirentINode,
    InodeType.JFFS2_NODETYPE_INODE: RawINode,
    InodeType.JFFS2_NODETYPE_CLEANMARKER: None}
