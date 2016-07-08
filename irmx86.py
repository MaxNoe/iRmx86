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

RMXVolumeInformation = namedtuple(
    'RMXVolumeInformation',
    [
        'name',
        'file_driver',
        'block_size',
        'volume_size',
        'num_fnodes',
        'fnode_start',
        'fnode_size',
        'root_fnode',
    ]

)


class FileSystem:
    def __init__(self, filename):
        self.fp = open(filename, 'rb')
        self._read_iso_vol_label()
        self._read_rmx_volume_information()

    def _read_iso_vol_label(self):

        raw_data = self._read_without_position_change(768, 128)

        (
            label, name, structure, recording_side,
            interleave_factor, iso_version
        ) = struct.unpack('3sx6ss60xs4x2sxs48x', raw_data)

        label = label.decode('ascii').strip()
        name = name.decode('ascii').strip()
        recording_side = int(recording_side)
        structure = structure.decode('ascii').strip()
        interleave_factor = int(interleave_factor)
        iso_version = int(iso_version)

        self.iso_volume_label = ISOVolumeLabel(
            label, name, structure, recording_side,
            interleave_factor, iso_version
        )

    def _read_without_position_change(self, start, num_bytes):
        current_position = self.fp.tell()
        self.fp.seek(start, 0)
        b = self.fp.read(num_bytes)
        self.fp.seek(current_position, 0)

        return b

    def _read_rmx_volume_information(self):
        raw_data = self._read_without_position_change(384, 128)

        (
            name, file_driver, block_size, volume_size,
            num_fnodes, fnode_start, fnode_size, root_fnode
        ) = struct.unpack('<10sxBHIHIHH100x', raw_data)
        name = name.decode().strip('\x00')
        # file_driver = int(file_driver)

        self.rmx_volume_information = RMXVolumeInformation(
            name, file_driver, block_size, volume_size,
            num_fnodes, fnode_start, fnode_size, root_fnode
        )


    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.fp.close()


if __name__ == '__main__':

    with FileSystem(sys.argv[1]) as f:
        pprint(f.iso_volume_label)
        pprint(f.rmx_volume_information)
