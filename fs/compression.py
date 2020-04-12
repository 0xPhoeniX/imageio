from fs.utils import hexdump
import logging


log = logging.getLogger(__name__)


class Compressor:
    def decompress(self, data, dsize=None):
        raise NotImplementedError


class DummyCompressor(Compressor):
    def decompress(self, data, dsize=None):
        return data


class GzipCompressor(Compressor):

    def decompress(self, data, dsize=None):
        import gzip
        return gzip.decompress(data)


class ZeroCompressor(Compressor):
    def decompress(self, data, dsize=None):
        return '\x00' * dsize


class RTimeCompressor(Compressor):
    def decompress(self, data, dsize=None):
        positions = [0] * 256
        cpage_out = bytearray([0] * dsize)
        outpos = 0
        pos = 0
        while outpos < dsize:
            value = ord(data[pos])
            pos += 1
            cpage_out[outpos] = value
            outpos += 1
            repeat = ord(data[pos])
            pos += 1

            backoffs = positions[value]
            positions[value] = outpos
            if repeat:
                if backoffs + repeat >= outpos:
                    while repeat:
                        cpage_out[outpos] = cpage_out[backoffs]
                        outpos += 1
                        backoffs += 1
                        repeat -= 1
                else:
                    cpage_out[outpos:outpos + repeat] = cpage_out[backoffs:backoffs + repeat]
                    outpos += repeat
        return bytes(cpage_out)


class ZLibCompressor(Compressor):

    def decompress(self, data, dsize=None):
        import zlib
        return zlib.decompress(data)


class XZCompressor(Compressor):

    def decompress(self, data, dsize=None):
        import lzma
        return lzma.decompress(data)


class LZMACompressor(Compressor):

    def decompress(self, data, dsize=None):
        import lzma
        return lzma.decompress(data)


class LZOCompressor(Compressor):

    def decompress(self, data, dsize=None):
        import lzo
        result = ''
        try:
            result = lzo.decompress(data, False, dsize)
            return result
        except lzo.error as e:
            log.debug(e)


class LZ4Compressor(Compressor):
    def decompress(self, data, dsize=None):
        raise NotImplementedError


class ZSTDCompressor(Compressor):
    def decompress(self, data, dsize=None):
        raise NotImplementedError
