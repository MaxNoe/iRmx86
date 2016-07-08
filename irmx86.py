import sys
import struct
from pprint import pprint
from collections import namedtuple

ISOVolumeLabel = namedtuple(
    'ISOVolumeLabel',
    [
        'label', 'name', 'structure', 'recording_side',
        'interleave_factor', 'iso_version'
    ]
)


class FileSystem:
    def __init__(self, filename):
        self.fp = open(filename, 'rb')
        self._read_iso_vol_label()

    def _read_iso_vol_label(self):

        current_position = self.fp.tell()

        self.fp.seek(768)

        (
            label, name, structure, recording_side,
            interleave_factor, iso_version
        ) = struct.unpack('3sx6ss60xs4x2sxs48x', self.fp.read(128))
        label = label.decode('ascii')
        name = name.decode('ascii')
        recording_side = int(recording_side)
        structure = structure.decode('ascii')
        interleave_factor = int(interleave_factor)
        iso_version = int(iso_version)

        self.fp.seek(current_position, 0)
        self.iso_volume_label = ISOVolumeLabel(
            label, name, structure, recording_side, interleave_factor, iso_version
        )

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.fp.close()


if __name__ == '__main__':

    with FileSystem(sys.argv[1]) as f:
        pprint(f.iso_volume_label)
