import sys
sys.path.append('../')

from fs.squashfs import SquashImage
from fs.jffs2 import JffsImage
from fs.utils import hexdump


def dumpFromSquash(path):
    print("Part of /bin/busybox from Squash Image")
    img = SquashImage.createObject(path)
    if img:
        print(hexdump(img.getFileData('/bin/busybox')[:256]))


def dumpFromJFFS2(path):
    print("Part of /bin/busybox from Jffs2 Image")
    img = JffsImage.createObject(path)
    if img:
        print(hexdump(img.getFileData('/bin/busybox')[:256]))


if __name__ == '__main__':
    dumpFromSquash('../images/example_xz.squash')
    dumpFromJFFS2('../images/example.jffs2')
