import logging
from struct import unpack
from fs.jffs2_types import *
from stat import S_ISDIR

log = logging.getLogger(__name__)


# http://www.inf.u-szeged.hu/projectdirs/jffs2/jffs2-anal/node4.html
def PAD(x):
    return (((x) + 3) & ~3)


class JffsImage():
    def __init__(self, path, endianess):
        self.version = 2
        self.f = open(path, 'rb')
        self.endianess = endianess
        self.nodes = {}
        self.tree = {'/': {'type': FTypes.DT_DIR, 'sibs': {}, 'id': 1}}
        self._loadInodeTable()
        for ino in self.nodes:
            self._dive(self.tree, self.nodes[ino])
        for ino in self.nodes:
            if self.nodes[ino]['dentry'].dtype == FTypes.DT_DIR:
                self.nodes[1] = self._genRootInode(self.nodes[ino])
                break

    def _genRootInode(self, src):
        '''
            JFFS2 does not have root inode. The function generate
            dummy root inode to support easy fs traversal.
            Dummy node is generated from first dir node found in
            inode list.
        '''
        a = DirentINode(src['dentry'].magic, src['dentry'].nodetype,
                        src['dentry'].totlen, src['dentry'].hdr_crc,
                        0, 0, 1, src['dentry'].mctime, 1, src['dentry'].dtype,
                        0, src['dentry'].node_crc, src['dentry'].name_crc, '/',
                        True, True, True)
        b = RawINode(src['vers'][0].magic, src['vers'][0].nodetype,
                     src['vers'][0].totlen, src['vers'][0].hdr_crc,
                     0, 0, src['vers'][0].mode, src['vers'][0].uid, src['vers'][0].gid,
                     0, src['vers'][0].atime, src['vers'][0].mtime, src['vers'][0].ctime,
                     0, 0, 0, 0, 0, 0, 0, src['vers'][0].node_crc, b'', True, True)
        return {'dentry': a, 'vers': [b]}

    def _loadInodeTable(self):
        retry = 0
        while True:
            cpos = self.f.tell()
            try:
                node = GeneralINode.unpack(self.f, self.endianess)
                if not node.hdr_crc_match:
                    log.error("[LoadInodeTable] Node Header CRC missmatch!", node)
                    raise Exception("Node header corrupted")
                self.f.seek(cpos)
                if node.nodetype == InodeType.JFFS2_NODETYPE_CLEANMARKER:
                    pass
                elif node.nodetype == InodeType.JFFS2_NODETYPE_DIRENT:
                    node = DirentINode.unpack(self.f, self.endianess)
                    if node.ino in self.nodes:
                        log.error("[LoadInodeTable] Existing ino: ", node)
                        raise Exception("The dirent already in the log.")
                    self.nodes[node.ino] = {'vers': [], 'dentry': node}
                elif node.nodetype == InodeType.JFFS2_NODETYPE_INODE:
                    node = RawINode.unpack(self.f, self.endianess)
                    self.nodes[node.ino]['vers'].append(node)
                offset = PAD(node.totlen)
                retry = 0
            except ValueError:
                log.debug("[LoadInodeTable] Can't unpack node, skipping byte @ 0x%x" % (cpos + offset))
                offset = 1
                if retry > 12:
                    break
                retry += 1
            self.f.seek(cpos + offset)

    def _dive(self, tree, item):
        for fname in tree:
            if tree[fname]['id'] == item['dentry'].pino:
                if item['dentry'].dtype == FTypes.DT_DIR:
                    tree[fname]['sibs'][item['dentry'].name] = {'type': item['dentry'].dtype,
                                                                'sibs': {},
                                                                'id': item['dentry'].ino}
                else:
                    tree[fname]['sibs'][item['dentry'].name] = {'id': item['dentry'].ino,
                                                                'type': item['dentry'].dtype,
                                                                'vers': len(item['vers'])}
                break
            elif tree[fname]['type'] == FTypes.DT_DIR:
                self._dive(tree[fname]['sibs'], item)

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
            if tree[last]['type'] == FTypes.DT_DIR:
                for item in tree[last]['sibs']:
                    yield item
            else:
                yield last
        except KeyError:
            log.debug("[ListPath] Can't find path: %s" % path)
            return

    def getFileData(self, path):
        inode = self._getINode(path)
        if inode is None:
            return None
        data = None
        try:
            data = inode['data']
        except KeyError:
            data = bytearray(inode['vers'][0].isize)
            for item in inode['vers']:
                data[item.offset:(item.offset + item.dsize)] = item.data    # TODO -> handle data dubliction
            inode['data'] = data
        return bytes(data)

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
            inode = self.nodes[tree[last]['id']]
        except KeyError:
            log.debug("[GetINode] Can't find iNode by path: %s" % path)
            pass
        return inode

    def getAttrs(self, path):
        inode = self._getINode(path)
        attrs = None
        if inode:
            attrs = {'st_atime': inode['vers'][0].atime,
                     'st_ctime': inode['vers'][0].ctime,
                     'st_gid': inode['vers'][0].gid,
                     'st_mode': inode['vers'][0].mode,
                     'st_mtime': inode['vers'][0].mtime,
                     'st_nlink': 1,
                     'st_size': inode['vers'][0].isize,
                     'st_uid': inode['vers'][0].uid,
                     'st_blocks': 0}
            if S_ISDIR(inode['vers'][0].mode):
                attrs['st_nlink'] = 2
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
                'st_blksize': 131072}

    def getLnkTarget(self, path):
        inode = self._getINode(path)
        result = None
        if inode:
            result = inode['vers'][0].data.decode('latin-1')
        return result

    @classmethod
    def createObject(cls, path, loglevel=logging.INFO):
        log.setLevel(loglevel)
        with open(path, 'rb') as f:
            data = f.read(2)
            bmagic = unpack('>H', data)[0]
            lmagic = unpack('<H', data)[0]
            endianess = None
            if bmagic == JFFS2_MAGIC_BITMASK:
                log.info("[CreateObject] Big endian, Jffs2 image.")
                endianess = ">"
            elif lmagic == JFFS2_MAGIC_BITMASK:
                log.info("[CreateObject] Little endian, Jffs2 image.")
                endianess = "<"
            else:
                return None
            return JffsImage(path, endianess)
