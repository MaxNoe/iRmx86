import sys
import struct
from collections import namedtuple
import os

filetypes = {
    0: 'fnode_file',
    1: 'free_space_map',
    2: 'free_fnodes_map',
    3: 'space_accounting_file',
    4: 'bad_device_blocks_file',
    6: 'directory',
    8: 'data',
    9: 'unknown',
}

Flags = namedtuple('Flags', ['allocated', 'long_file', 'modified', 'deleted'])

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

FileNode = namedtuple(
    'FileNode',
    [
        'flags', 'type', 'granularity', 'owner', 'creation_time', 'access_time',
        'modification_time', 'total_size', 'total_blocks', 'block_pointers',
        'size', 'id_count', 'access_rights', 'parent',
    ]
)

BlockPointer = namedtuple('BlockPointer', ['num_blocks', 'first_block'])


class FileSystem:
    def __init__(self, filename):
        self.fp = open(filename, 'rb')
        self._read_iso_vol_label()
        self._read_rmx_volume_information()
        self._read_fnode_file()

    def _read_without_position_change(self, start, num_bytes):
        current_position = self.fp.tell()
        self.fp.seek(start, 0)
        b = self.fp.read(num_bytes)
        self.fp.seek(current_position, 0)

        return b

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

    def _read_rmx_volume_information(self):
        raw_data = self._read_without_position_change(384, 128)

        (
            name, file_driver, block_size, volume_size,
            num_fnodes, fnode_start, fnode_size, root_fnode
        ) = struct.unpack('<10sxBHIHIHH100x', raw_data)
        name = name.decode().strip('\x00')
        file_driver = int(file_driver)

        self.rmx_volume_information = RMXVolumeInformation(
            name, file_driver, block_size, volume_size,
            num_fnodes, fnode_start, fnode_size, root_fnode
        )

    def _read_fnode_file(self):
        start = self.rmx_volume_information.fnode_start
        num_fnodes = self.rmx_volume_information.num_fnodes
        fnode_size = self.rmx_volume_information.fnode_size

        raw_data = self._read_without_position_change(
            start, num_fnodes * fnode_size,
        )

        self.fnodes = []
        for i in range(num_fnodes):
            fnode_data = raw_data[i * fnode_size: (i + 1) * fnode_size]
            fnode = self._read_fnode(fnode_data)

            if fnode.flags.allocated:
                self.fnodes.append(fnode)

    def _read_fnode(self, raw_data):
        fmt = '<HBBHIIIII40sI4xH9sH'
        fmt_size = struct.calcsize(fmt)
        num_aux_bytes = self.rmx_volume_information.fnode_size - fmt_size

        elems = struct.unpack(fmt + '{}x'.format(num_aux_bytes), raw_data)

        (
            flags, file_type, granularity, owner, creation_time,
            access_time, modification_time, total_size, total_blocks,
            pointer_data, size, id_count, accessor_data, parent
        ) = elems

        flags = self._parse_flags(flags)
        file_type = filetypes[file_type]
        pointers = self._parse_pointer_data(pointer_data)

        if flags.long_file:
            block_pointers = []
            for num_blocks, first_block in pointers:
                block_pointers.extend(
                    self._parse_indirect_blocks(num_blocks, first_block)
                )
        else:
            block_pointers = pointers

        return FileNode(
            flags, file_type, granularity, owner, creation_time,
            access_time, modification_time, total_size, total_blocks,
            block_pointers, size, id_count, accessor_data, parent
        )

    def _parse_pointer_data(self, data):
        fmt = '<H3s'
        s = struct.calcsize(fmt)
        pointers = []
        for start in range(0, 8 * s, s):
            num_blocks, block_address = struct.unpack(fmt, data[start: start + s])

            if num_blocks == 0:
                continue

            block_address = self._read_24bit_integer(block_address)
            pointers.append(BlockPointer(num_blocks, block_address))

        return pointers

    @staticmethod
    def _read_24bit_integer(data):
        val, = struct.unpack('<I', data + b'\x00')
        return val

    def _parse_indirect_blocks(self, num_blocks, first_block):
        fmt = '<B3s'
        s = struct.calcsize(fmt)
        data = self._read_without_position_change(
            first_block, num_blocks * s
        )

        indirect_blocks = []
        for start in range(0, num_blocks * s, s):
            num_blocks, block_address = struct.unpack(fmt, data[start: start + s])
            block_address = self._read_24bit_integer(block_address)
            indirect_blocks.append(BlockPointer(num_blocks, block_address))

        return indirect_blocks

    @staticmethod
    def _parse_flags(flags):
        flags = '{0:016b}'.format(flags)[::-1]

        flags = list(map(lambda x: bool(int(x)), flags))
        flags = Flags(
            allocated=flags[0],
            long_file=flags[1],
            modified=flags[5],
            deleted=flags[6],
        )

        return flags

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.fp.close()

    def _get_file_data(self, fnode):
        return self._gather_blocks(fnode.block_pointers)

    def _gather_blocks(self, block_pointers):
        content = b''

        for num_blocks, first_block in block_pointers:
            content += self._read_blocks(num_blocks, first_block)

        return content

    def _read_blocks(self, num_blocks, first_block):
        ''' read  `num_blocks` volume blocks starting from `first_block` '''
        return self._read_without_position_change(
            first_block * self.rmx_volume_information.block_size,
            num_blocks * self.rmx_volume_information.block_size
        )

    def _read_directory(self, fnode):
        assert fnode.type == 'directory'

        data = self._get_file_data(fnode)
        fmt = 'H14s'
        size = struct.calcsize(fmt)
        files = {}
        for first_byte in range(0, len(data), size):
            fnode, name = struct.unpack(fmt, data[first_byte:first_byte + size])
            name = name.decode('ascii').strip('\x00')
            if self.fnodes[fnode].type in ('directory', 'data'):
                files[name] = self.fnodes[fnode]

        return files


if __name__ == '__main__':
    infile = sys.argv[1]
    isoname, ext = os.path.splitext(infile)
    with FileSystem(sys.argv[1]) as fs:

        root_fnode = fs.fnodes[fs.rmx_volume_information.root_fnode]
        files = fs._read_directory(root_fnode)
        os.makedirs(isoname, exist_ok=True)

        for name, fnode in files.items():
            if fnode.type == 'data':
                with open(os.path.join(isoname, name.replace(' ', '_')), 'wb') as f:
                    f.write(fs._get_file_data(fnode))
