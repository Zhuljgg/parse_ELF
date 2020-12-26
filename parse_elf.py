import sys
import binascii

ptype = {0x0: 'NULL',
         0x1: 'LOAD',
         0x2: 'DYNAMIC',
         0x3: 'INERP',
         0x4: 'NOTE',
         0x5: 'SHLIB',
         0x6: 'PHDR',
         0x7: 'TLS',
         0x8: 'NUM',
         0x60000000: 'LOOS',
         0x6474e550: 'GNU_EH_FRAME',
         0x6474e551: 'GNU_STACK',
         0x6474e552: 'GNU_RELRO',
         0x6ffffffa: 'LOSUNW',
         0x6ffffffc: 'SUNWBSS',
         0x6ffffffb: 'SUNWSTACK',
         0x6fffffff: 'HISUNW ',
         0x6ffffffe: 'HIOS',
         0x70000000: 'LOPROC',
         0x7fffffff: 'HIPROC',
         # ARM Sections
         0x70000001: 'ARM_EXIDX',
         0x70000002: 'ARM_PREEMPTMAP',
         0x70000003: 'ARM_ATTRIBUTES',
         0x70000004: 'ARM_DEBUGOVERLAY',
         0x70000005: 'ARM_OVERLAYSECTION'
         }

pflags = {
    0: 'N',
    1: '__E',
    2: '_W_',
    3: '_WE',
    4: 'R__',
    5: 'R_E',
    6: 'RW_',
    7: 'RWE',
}


class elf_header(object):
    def __init__(self):
        super(elf_header, self).__init__()
        self.e_ident = None
        self.e_type = None
        self.e_machine = None
        self.e_version = None
        self.e_entry = None
        self.e_phoff = None
        self.e_shoff = None
        self.e_flags = None
        self.e_ehsize = None
        self.e_phentsize = None
        self.e_phnum = None
        self.e_shentsize = None
        self.e_shnum = None
        self.e_shtrndx = None


class elf_header_e_ident(object):
    def __init__(self):
        super(elf_header_e_ident, self).__init__()
        self.file_identification = None
        self.ei_class = None
        self.ei_data = None
        self.ei_version = None
        self.ei_osabi = None
        self.ei_abiversion = None
        self.ei_pad = None
        self.ei_nident_size = None


class elf_p_table_element(object):
    def __init__(self):
        super(elf_p_table_element, self).__init__()
        self.p_type = None
        self.p_flags = None
        self.p_offset = None
        self.p_vaddr = None
        self.p_paddr = None
        self.p_filesz = None
        self.p_memsz = None
        self.p_align = None
        # char p_data[p_filesz]


class ELF():
    """parse ELF"""

    def __init__(self, filepath):
        # super(ELF, self).__init__()
        self.filepath = filepath
        self.elf_header = elf_header()

        self.elf_program_table = []

        self.init_elf_header()
        self.init_program_table()

    def init_elf_header(self):
        with open(self.filepath, "rb") as f:
            f.seek(0, 0)
            self.f = f
            self.elf_header.e_ident = elf_header_e_ident()
            self.elf_header.e_ident.file_identification = f.read(4)
            if self.elf_header.e_ident.file_identification != b'\x7fELF':
                raise Exception("not elf file")
            self.elf_header.e_ident.ei_class = int.from_bytes(
                f.read(1), 'little')
            self.elf_header.e_ident.ei_data = int.from_bytes(
                f.read(1), 'little')
            self.elf_header.e_ident.ei_version = int.from_bytes(
                f.read(1), 'little')
            self.elf_header.e_ident.ei_osabi = int.from_bytes(
                f.read(1), 'little')
            self.elf_header.e_ident.ei_abiversion = int.from_bytes(
                f.read(1), 'little')
            self.elf_header.e_ident.ei_pad = binascii.b2a_hex(f.read(6))
            self.elf_header.e_ident.ei_nident_size = int.from_bytes(
                f.read(1), 'little')

            self.elf_header.e_type = self._get_int(16, 2)
            # print(hex(self.elf_header.e_type))
            self.elf_header.e_machine = self._get_int(18, 2)
            # print(hex(self.elf_header.e_machine))
            self.elf_header.e_version = self._get_int(20, 4)
            self.elf_header.e_entry = self._get_int(24, 8)
            self.elf_header.e_phoff = self._get_int(32, 8)
            # print(hex(self.elf_header.e_phoff))
            self.elf_header.e_shoff = self._get_int(40, 8)
            self.elf_header.e_flags = self._get_int(48, 4)
            self.elf_header.e_ehsize = self._get_int(52, 2)
            self.elf_header.e_phentsize = self._get_int(54, 2)
            self.elf_header.e_phnum = self._get_int(56, 2)
            self.elf_header.e_shentsize = self._get_int(58, 2)
            self.elf_header.e_shnum = self._get_int(60, 2)
            self.elf_header.e_shtrndx = self._get_int(62, 2)

    def _get_int(self, seek, num):
        self.f.seek(seek, 0)
        return int.from_bytes(self.f.read(num), 'little')

    def init_program_table(self):
        for i in range(self.elf_header.e_phnum):
            self.elf_program_table.append(
                self.parse_program_header_element(
                    self.elf_header.e_phoff+i*self.elf_header.e_phentsize))

    def parse_program_header_element(self, offset):
        with open(self.filepath, "rb") as f:
            self.f = f
            self.f.seek(offset, 0)
            p_element = elf_p_table_element()
            p_element.p_type = int.from_bytes(
                self.f.read(4), 'little')
            p_element.p_flags = int.from_bytes(
                self.f.read(4), 'little')
            p_element.p_offset = int.from_bytes(
                self.f.read(8), 'little')
            p_element.p_vaddr = int.from_bytes(
                self.f.read(8), 'little')
            p_element.p_paddr = int.from_bytes(
                self.f.read(8), 'little')
            p_element.p_filesz = int.from_bytes(
                self.f.read(8), 'little')
            p_element.p_memsz = int.from_bytes(
                self.f.read(8), 'little')
            p_element.p_align = int.from_bytes(
                self.f.read(8), 'little')
            return p_element

    def display_ele_type_flags(self):
        print('=== Program Header Table ===')
        for index in range(len(self.elf_program_table)):
            element = self.elf_program_table[index]
            if element.p_type in ptype and element.p_flags in pflags:
                print(
                    f'{ptype[element.p_type]} : {pflags[element.p_flags]}')


if __name__ == "__main__":
    try:
        elf = ELF('1.so')
        elf.init_elf_header()
        elf.display_ele_type_flags()
    except Exception as e:
        print(f'ERROR:{e}')
