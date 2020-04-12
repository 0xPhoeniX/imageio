from fs.squashfs_types import *
from struct import unpack, calcsize
from fs.compression import *
from stat import S_IFDIR, S_IFLNK, S_IFREG
import logging


log = logging.getLogger(__name__)

# Info
# https://github.com/AgentD/squashfs-tools-ng/blob/master/doc/format.txt
compressors = [DummyCompressor,
               GzipCompressor,
               LZMACompressor,
               LZOCompressor,
               XZCompressor,
               LZ4Compressor,
               ZSTDCompressor]


def getCompressor(comp_id):
    try:
        return compressors[comp_id]()
    except Exception:
        raise Exception("Unknown compression: %d" % comp_id)


class SquashImage:
    def __init__(self, path, endianess):
        self.IdTable = None
        self.FragTable = []
        self.endianess = endianess
        self.tree = {}
        self.f = open(path, 'rb')

        self.super_block = SuperBlock.unpack(self.f, endianess)
        log.debug(self.super_block)
        # for flag in SuperblockFlags:
        #     if (SuperblockFlags[flag] & self.super_block.flags) == SuperblockFlags[flag]:
        #         print(flag)

        self.inodeTable = [None] * (self.super_block.inode_count + 1)
        self.root_meta_blk = (self.super_block.root_inode_ref >> 16)
        self.root_blk_off = (self.super_block.root_inode_ref & 0xFFFF)
        self.compressor = getCompressor(self.super_block.compression_id.value)
        self._loadIdTable()
        self._loadInodeTable()
        self._loadFragTable()
        self.tree['/'] = self._buildTree(self.root_inode)

    def _getMetadataBlob(self):
        hdr = MetadataBlock.unpack(self.f, self.endianess)
        blob_data = self.f.read(hdr.dlen)
        if hdr.comp:
            blob_data = self.compressor.decompress(blob_data, 0x2000)
        return blob_data

    def _loadInodeTable(self):
        curPos = self.f.tell()
        inode_data = bytearray()
        end = self.super_block.directory_table_start

        self.f.seek(self.super_block.inode_table_start + self.root_meta_blk)
        root_blk_data = self._getMetadataBlob()
        inode_type = unpack(self.endianess + "H",
                            root_blk_data[self.root_blk_off:self.root_blk_off + 2])[0]
        self.root_inode = node_index[inode_type].unpack(root_blk_data[self.root_blk_off:],
                                                        self.endianess, self.IdTable)

        self.f.seek(self.super_block.inode_table_start)
        while end > self.f.tell():
            inode_data.extend(self._getMetadataBlob())
        self.f.seek(curPos)

        offset = 0
        end = len(inode_data)
        type_fmt = self.endianess + "H"
        while end > offset:
            inode_type = unpack(type_fmt, inode_data[offset:offset + 2])[0]
            inode = node_index[inode_type].unpack(inode_data[offset:],
                                                  self.endianess, self.IdTable)
            self.inodeTable[inode.inode_number] = inode
            offset = offset + inode.dlen

    def _loadIdTable(self):
        table_data = bytearray()
        offsets = int(ceil(self.super_block.id_count / 2048.0))
        curPos = self.f.tell()
        self.f.seek(self.super_block.id_table_start)
        data = self.f.read(offsets * 8)
        offsets_lst = list(unpack(self.endianess + "%dQ" % offsets, data))
        for off in offsets_lst:
            self.f.seek(off)
            table_data.extend(self._getMetadataBlob())
        self.IdTable = list(unpack(self.endianess + "%dI" % self.super_block.id_count, table_data))
        self.f.seek(curPos)

    def _loadFragTable(self):
        curPos = self.f.tell()
        self.f.seek(self.super_block.fragment_table_start)
        fmt = self.endianess + "%dQ" % int(ceil(self.super_block.fragment_entry_count / 512.0))
        frag_blk_entries_offsets = list(unpack(fmt, self.f.read(calcsize(fmt))))
        for item in frag_blk_entries_offsets:
            self.f.seek(item)
            data = self._getMetadataBlob()
            offset = 0
            end = len(data)
            while end > offset:
                fbe = FragmentBlockEntry.unpack(data[offset:], self.endianess)
                self.FragTable.append(fbe)
                offset += fbe.dlen
        self.f.seek(curPos)

    def _buildTree(self, inode):
        result = {'type': inode.inode_type, 'sibs': {}, 'id': inode.inode_number}
        if inode.inode_number == 0 or inode.file_size <= 3:
            return result
        data = bytearray()
        self.f.seek(self.super_block.directory_table_start + inode.block_idx)
        offset = inode.block_offset
        end = offset + inode.file_size
        while end > len(data):
            data.extend(self._getMetadataBlob())

        # From observations - at the end of directory data the difference is always 3
        while (end - offset) > 3:
            dirHdr = DirectoryHeader.unpack(data[offset:], self.endianess)
            offset += dirHdr.dlen
            for i in range(0, dirHdr.count + 1):
                d = DirectoryEntry.unpack(data[offset:], self.endianess)
                if d.type == 1 or d.type == 8:
                    node = self.inodeTable[dirHdr.node_number + d.inode_offset]
                    result['sibs'][d.name] = self._buildTree(node)
                else:
                    result['sibs'][d.name] = {'id': dirHdr.node_number + d.inode_offset,
                                              'type': d.type}
                offset += d.dlen
        return result

    def _getINode(self, path):
        if path == '/':
            p = []
        else:
            p = path.split('/')[1:]
        tree = self.tree
        last = '/'
        inode = None
        try:
            for item in p:
                tree = tree[last]['sibs']
                last = item
            inode = self.inodeTable[tree[last]['id']]
        except KeyError:
            log.debug("[GetINode] Can't find iNode by path: %s" % path)
            return
        return inode

    def listPath(self, path):
        if path == '/':
            p = []
        else:
            p = path.split('/')[1:]
        tree = self.tree
        last = '/'
        try:
            for item in p:
                tree = tree[last]['sibs']
                last = item
            if tree[last]['type'] == 1 or tree[last]['type'] == 8:
                for item in tree[last]['sibs']:
                    yield item
            else:
                yield last
        except KeyError:
            log.debug("[ListPath] Can't find path: %s" % path)
            return

    def getFileData(self, path):
        log.debug(">>>>>>>>>>>>>>>>>getFileData<<<<<<<<<<<<<<<<<<<")
        inode = self._getINode(path)
        if inode is None:
            log.debug("No inode for: ", path)
            return None
        data = bytearray()
        log.debug(inode)
        if inode.inode_type == 2:
            self.f.seek(inode.blocks_start)
            for bsize in inode.block_sizes:
                is_compressed = not ((bsize & 0x800000) >> 24)
                dsize = (bsize & 0x7FFFFF)
                tmp = self.f.read(dsize)
                log.debug("\t[%d] -> compr %d, dsize %d" % (bsize, is_compressed, dsize))
                if is_compressed:
                    ''' The output buffer size is for LZO compression case
                        otherwise the size will be ignored.
                    '''
                    tmp = self.compressor.decompress(tmp, 0x40000)
                data.extend(tmp)
            if inode.fragment_block_index != 0xFFFFFFFF:
                frag = self.FragTable[inode.fragment_block_index]
                log.debug(frag)
                self.f.seek(frag.start)
                frag_data = self.f.read(frag.size)
                if frag.comp:
                    frag_data = self.compressor.decompress(frag_data, 0x40000)
                data.extend(frag_data[inode.block_offset:(inode.block_offset + inode.file_size)])
        return bytes(data)

    def getAttrs(self, path):
        inode = self._getINode(path)
        attrs = None
        if inode:
            attrs = {'st_atime': inode.modified_time,
                     'st_ctime': inode.modified_time,
                     'st_gid': inode.gid,
                     'st_mode': 0,
                     'st_mtime': inode.modified_time,
                     'st_nlink': 0,
                     'st_size': 0,
                     'st_uid': inode.uid,
                     'st_blocks': 0}
            if inode.inode_type == 2:
                attrs['st_mode'] = S_IFREG | inode.permissions
                attrs['st_nlink'] = 1
                attrs['st_size'] = inode.file_size
            elif inode.inode_type == 1 or inode.inode_type == 8:
                attrs['st_mode'] = S_IFDIR | inode.permissions
                attrs['st_nlink'] = inode.hard_link_count
            elif inode.inode_type == 3:
                attrs['st_mode'] = S_IFLNK | inode.permissions
                attrs['st_nlink'] = inode.hard_link_count
        return attrs

    def getStatFs(self):
        return {'f_bavail': 0,
                'f_bfree': 0,
                'f_blocks': 0,
                'f_bsize': 0,
                'f_favail': 0,
                'f_ffree': 0,
                'f_files': 0,
                'f_flag': 0,
                'f_frsize': 0,
                'f_namemax': 255,
                'st_blocks': 0,
                'st_blksize': self.super_block.block_size}

    def getLnkTarget(self, path):
        inode = self._getINode(path)
        if inode:
            return inode.target_path

    @classmethod
    def createObject(cls, path, loglevel=logging.INFO):
        log.setLevel(loglevel)
        with open(path, 'rb') as f:
            data = f.read(4)
            bmagic = unpack('>I', data)[0]
            lmagic = unpack('<I', data)[0]
            endianess = None
            if bmagic == SQUASHFS_MAGIC:
                log.info("[CreateObject] Big endian, Squash image.")
                endianess = ">"
            elif lmagic == SQUASHFS_MAGIC:
                log.info("[CreateObject] Little endian, Squash image.")
                endianess = "<"
            else:
                return None
            return SquashImage(path, endianess)
