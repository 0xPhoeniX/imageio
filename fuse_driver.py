from errno import ENOENT
import errno
from fuse import FUSE, FuseOSError, Operations
import logging
import argparse
import fs.squashfs
import fs.jffs2
import sys


log = logging.getLogger("imageIO")
log.setLevel(logging.INFO)


supported_filesystems = [fs.squashfs.SquashImage,
                         fs.jffs2.JffsImage]


class FSDriver(Operations):

    def __init__(self, imgObj):
        self.image = imgObj
        self.fd = 0

    # Filesystem methods
    # ==================

    def access(self, path, mode):
        pass

    def chmod(self, path, mode):
        raise FuseOSError(errno.EROFS)

    def chown(self, path, uid, gid):
        raise FuseOSError(errno.EROFS)

    def getattr(self, path, fh=None):
        log.debug("[getattr] %s" % path)
        attrs = self.image.getAttrs(path)
        if attrs:
            return attrs
        raise FuseOSError(ENOENT)

    def readdir(self, path, fh):
        yield '.'
        yield ".."
        for item in self.image.listPath(path):
            yield item

    def readlink(self, path):
        trg = self.image.getLnkTarget(path)
        if trg:
            return trg
        return FuseOSError(errno.EROFS)

    def mknod(self, path, mode, dev):
        raise FuseOSError(errno.EROFS)

    def rmdir(self, path):
        raise FuseOSError(errno.EROFS)

    def mkdir(self, path, mode):
        raise FuseOSError(errno.EROFS)

    def statfs(self, path):
        return self.image.getStatFs()

    def unlink(self, path):
        raise FuseOSError(errno.EROFS)

    def symlink(self, target, name):
        raise FuseOSError(errno.EROFS)

    def rename(self, old, new):
        raise FuseOSError(errno.EROFS)

    def link(self, target, name):
        raise FuseOSError(errno.EROFS)

    def utimens(self, path, times=None):
        raise FuseOSError(errno.EROFS)

    # File methods
    # ============

    def open(self, path, flags):
        self.fd += 1
        return self.fd

    def create(self, path, mode, fi=None):
        raise FuseOSError(errno.EROFS)

    def read(self, path, length, offset, fh):
        data = self.image.getFileData(path)
        if data:
            return data[offset: (offset + length)]
        raise FuseOSError(errno.ENOENT)

    def write(self, path, buf, offset, fh):
        raise FuseOSError(errno.EROFS)

    def truncate(self, path, length, fh=None):
        raise FuseOSError(errno.EROFS)

    def flush(self, path, fh):
        pass

    def release(self, path, fh):
        pass

    def fsync(self, path, fdatasync, fh):
        pass


def main(fusebox, mountpoint, conf_file=None):
    # Need to set user_allow_other in /etc/fuse.conf for
    # allow_other option to work (or run this process as root)
    # #fusebox = FuseBox(conf_file)
    FUSE(fusebox, mountpoint, foreground=True, allow_other=True, nothreads=True)


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    logging.basicConfig(level=logging.INFO)

    p.add_argument("-d", "--debug", action='store_true', dest='debug',
                   help="turn on debugging output")
    p.add_argument("-m", "--mount_point", required=True, help="Mount directory")
    p.add_argument("rootfs", help="Image file to mount")
    args = p.parse_args()
    loglevel = logging.INFO
    if args.debug:
        loglevel = logging.DEBUG
    log.setLevel(level=loglevel)

    if args.mount_point and args.rootfs:
        for fscls in supported_filesystems:
            imgObj = fscls.createObject(args.rootfs, loglevel)
            if imgObj:
                main(FSDriver(imgObj), args.mount_point)
                sys.exit(0)
        log.warning("Unsupported image type!")
    log.error("Check your parameters!")
