import struct
from pefile import PE
from typing import List, Tuple


# Consts
# the offset of the fields in the load config struct, TODO: define (or find a python definition of) the full struct
DYNAMIC_RELOC_TABLE_OFFSET_FIELD_OFFSET = 0xe0


class DRTException(BaseException):
    pass


class IMAGE_DYNAMIC_RELOCATION_TABLE:
    sizeof = 8

    def __init__(self):
        self.version: int = None
        self.size: int = None
        self.dynamic_relocations: List[IMAGE_DYNAMIC_RELOCATION] = None

    @classmethod
    def from_pe(cls, pe: PE) -> 'IMAGE_DYNAMIC_RELOCATION_TABLE':
        """
        Creates a DRT from a PE file object
        :param pe: PE file object
        :return: IMAGE_DYNAMIC_RELOCATION_TABLE
        """
        drt = cls()
        # TODO verify dir is not none is enough
        if not (hasattr(pe, 'DIRECTORY_ENTRY_LOAD_CONFIG') and pe.DIRECTORY_ENTRY_LOAD_CONFIG is not None):
            raise DRTException("PE has no load config!")
        load_config_base_offset = pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.get_file_offset()
        dynamic_reloc_table_offset = pe.get_dword_from_offset(
            load_config_base_offset + DYNAMIC_RELOC_TABLE_OFFSET_FIELD_OFFSET)
        dynamic_reloc_table_section = pe.get_word_from_offset(
            load_config_base_offset + DYNAMIC_RELOC_TABLE_OFFSET_FIELD_OFFSET + 4)
        if dynamic_reloc_table_section == 0 or dynamic_reloc_table_offset == 0:
            raise DRTException("PE ha no dynamic relocation table!")
        # the dynamic_reloc_table_section is the section that contains the DRT and all the offsets are relative to its base
        assert dynamic_reloc_table_section <= len(
            pe.sections), 'dynamic reloc table section is out of bounds for the PE'
        base_section_offset = pe.sections[dynamic_reloc_table_section - 1].get_PointerToRawData_adj()
        drt.version, drt.size = struct.unpack('<II', pe.__data__[base_section_offset + dynamic_reloc_table_offset:
                                                                   base_section_offset + dynamic_reloc_table_offset + drt.sizeof])
        # according to research, version is always 1
        assert drt.version == 1, 'Found version is not 1, wrong data unpacked'
        drt.dynamic_relocations = []
        idx = 0
        dynamic_reloc_data = pe.__data__[base_section_offset + dynamic_reloc_table_offset + drt.sizeof:
                                         base_section_offset + dynamic_reloc_table_offset + drt.sizeof + drt.size]
        while idx <= drt.size - IMAGE_DYNAMIC_RELOCATION.sizeof:
            reloc = IMAGE_DYNAMIC_RELOCATION.from_bytes(dynamic_reloc_data[idx:])
            idx += reloc.base_reloc_size + IMAGE_DYNAMIC_RELOCATION.sizeof
            drt.dynamic_relocations.append(reloc)
        return drt

    @classmethod
    def from_data(cls, dynamic_relocations: List['IMAGE_DYNAMIC_RELOCATION']) -> 'IMAGE_DYNAMIC_RELOCATION_TABLE':
        """
        Creates a DRT from a list of dynamic relocations
        :param dynamic_relocations: List of dynamic relocations
        :return: DRT
        """
        drt = cls()
        drt.version = 1
        drt.size = 0
        for dynamic_relocation in dynamic_relocations:
            drt.size += IMAGE_DYNAMIC_RELOCATION.sizeof + dynamic_relocation.base_reloc_size
        drt.dynamic_relocations = dynamic_relocations
        return drt

    def __repr__(self) -> str:
        return f"Version: {self.version} | Size: {hex(self.size)}\n" \
               f"Dynamic Relocation Data: {self.dynamic_relocations}"

    def dump(self) -> bytearray:
        """
        Dumps the dynamic relocation table into a packed struct (its raw form in the binary)
        :return: Packed DRT
        """
        packed_drt = bytearray(struct.pack('<II', self.version, self.size))
        for dynamic_relocation in self.dynamic_relocations:
            packed_drt += dynamic_relocation.dump()
        return packed_drt


class IMAGE_DYNAMIC_RELOCATION:
    sizeof = 12

    def __init__(self):
        self.symbol: int = None
        self.base_reloc_size: int = None
        self.base_relocations: List[IMAGE_BASE_RELOCATION] = []
        self.function_override_info: IMAGE_FUNCTION_OVERRIDE_HEADER = None

    @classmethod
    def from_bytes(cls, raw_data: bytes) -> 'IMAGE_DYNAMIC_RELOCATION':
        """
        Creates a IMAGE_DYNAMIC_RELOCATION from raw data
        :param raw_data: IMAGE_DYNAMIC_RELOCATION raw data
        :return: IMAGE_DYNAMIC_RELOCATION
        """
        dynamic_reloc = cls()
        dynamic_reloc.symbol, dynamic_reloc.base_reloc_size = struct.unpack('<QI', raw_data[:dynamic_reloc.sizeof])
        assert dynamic_reloc.sizeof + dynamic_reloc.base_reloc_size <= len(raw_data), \
            f'Parsed dynamic reloc length is too big: {dynamic_reloc.base_reloc_size}'
        reloc_data = raw_data[dynamic_reloc.sizeof : dynamic_reloc.sizeof + dynamic_reloc.base_reloc_size]
        dynamic_reloc.base_relocations = []
        # ARM, prologue and epilogue related stuff
        if dynamic_reloc.symbol in (1,2,6):
            return dynamic_reloc
        # Function Override (ltfs) stuff
        elif dynamic_reloc.symbol == 7:
            dynamic_reloc.function_override_info = IMAGE_FUNCTION_OVERRIDE_HEADER.from_bytes(reloc_data)
        # Retpoline, import optimization and KASLR
        else:
            idx = 0
            while idx <= dynamic_reloc.base_reloc_size - IMAGE_BASE_RELOCATION.sizeof:
                reloc = IMAGE_BASE_RELOCATION.from_bytes(reloc_data[idx:])
                idx += reloc.size_of_block
                dynamic_reloc.base_relocations.append(reloc)
        return dynamic_reloc

    @classmethod
    def from_data(cls, symbol: int, base_relocations: List['IMAGE_BASE_RELOCATION'], function_override_info: IMAGE_FUNCTION_OVERRIDE_HEADER) -> 'IMAGE_DYNAMIC_RELOCATION':
        dynamic_reloc = cls()
        dynamic_reloc.symbol = symbol
        dynamic_reloc.base_reloc_size = sum([reloc.size_of_block for reloc in base_relocations])
        dynamic_reloc.base_relocations = base_relocations
        dynamic_reloc.function_override_info = function_override_info
        return dynamic_reloc

    def __repr__(self) -> str:
        return f"Symbol: {hex(self.symbol)} | Base Reloc Size: {hex(self.base_reloc_size)} \n" \
               f"Base Relocations: {self.base_relocations}\n" \
               f"Function Override Info: {self.function_override_info}\n"

    def dump(self) -> bytearray:
        packed_dynamic_reloc = bytearray(struct.pack('<QI', self.symbol, self.base_reloc_size))

        # Only one of these lists will have values
        for base_relocation in self.base_relocations:
            packed_dynamic_reloc += base_relocation.dump()
        if self.function_override_info:
            packed_dynamic_reloc += self.function_override_info.dump()

        return packed_dynamic_reloc


class IMAGE_BASE_RELOCATION:
    sizeof = 8

    def __init__(self):
        self.virtual_address: int = None
        self.size_of_block: int = None
        self.num_of_type_offsets: int = None

        # Tuple(rva, offset_type)
        self.type_offsets: List[Tuple[int, int]] = None
        self.has_padding: bool = None

    @classmethod
    def from_bytes(cls, raw_data: bytes) -> 'IMAGE_BASE_RELOCATION':
        """
        Creates an IMAGE_BASE_RELOCATION object from the raw data
        :param raw_data: raw data of the IMAGE_BASE_RELOCATION
        :return: IMAGE_BASE_RELOCATION object
        """
        reloc = cls()
        reloc.virtual_address, reloc.size_of_block = struct.unpack('<II', raw_data[:reloc.sizeof])
        reloc.num_of_type_offsets = int((reloc.size_of_block - reloc.sizeof) / 2)

        type_offset_list = struct.unpack('<' + 'H' * reloc.num_of_type_offsets, \
                                         raw_data[reloc.sizeof:reloc.sizeof + 2 * reloc.num_of_type_offsets])
        
        reloc.type_offsets = []
        for type_offset in type_offset_list:
            rva = reloc.virtual_address + (type_offset & 0xFFF)
            offset_type = type_offset >> 12
            reloc.type_offsets.append((rva, offset_type))

        reloc.has_padding = False
        # The last type offset is padding if there is an odd number of type offsets in the block
        if reloc.type_offsets[-1][0] - reloc.virtual_address == 0:
            reloc.type_offsets = reloc.type_offsets[:-1]
            reloc.has_padding = True
            reloc.num_of_type_offsets -= 1

        return reloc

    @classmethod
    def from_data(cls, virtual_address: int, type_offsets: List[Tuple[int, int]]) -> 'IMAGE_BASE_RELOCATION':
        """
        Creates an IMAGE_BASE_RELOCATION object from the given data
        :param virtual_address: virtual address of the base relocation
        :param type_offsets: list of tuples of (rva, offset_type)
        :return: IMAGE_BASE_RELOCATION object
        """
        base_reloc = cls()
        base_reloc.virtual_address = virtual_address
        # If there is an odd number of type offsets, add a padding type offset
        if len(type_offsets) % 2 != 0:
            base_reloc.num_of_type_offsets = len(type_offsets) + 1
            base_reloc.has_padding = True
        else:
            base_reloc.num_of_type_offsets = len(type_offsets)
            base_reloc.has_padding = False
        base_reloc.size_of_block = cls.sizeof + base_reloc.num_of_type_offsets * 2
        base_reloc.type_offsets = type_offsets
        return base_reloc

    def __repr__(self) -> str:
        return f'Virtual Address: {hex(self.virtual_address)} | size of Block: {hex(self.size_of_block)} | ' \
               f'Num of Type Offsets: {self.num_of_type_offsets} | ' \
               f'Type Offsest: {["RVA " + hex(offset) + " Type " + str(offset_type) for offset, offset_type in self.type_offsets]}\n'

    def dump(self) -> bytearray:
        # empty bytes at the end for padding
        packed_base_relocation = bytearray(struct.pack('<II' + 'H'*(len(self.type_offsets)), self.virtual_address,
                self.size_of_block, *[(rva & 0xFFF) + (offset_type << 12) for rva,offset_type in self.type_offsets]))
        if self.has_padding:
            packed_base_relocation += b'\x00\x00'
        return packed_base_relocation
    

class IMAGE_FUNCTION_OVERRIDE_DYNAMIC_RELOCATION:
    sizeof = 16

    def __init__(self):
        self.original_rva: int = None
        self.bdd_offset: int = None
        self.rva_size: int = None
        self.base_reloc_size: int = None
        self.rva_list: List[int] = None
        self.base_relocations: List[IMAGE_BASE_RELOCATION] = None
        self.total_size: int = None

    @classmethod
    def from_bytes(cls, raw_data: bytes) -> 'IMAGE_FUNCTION_OVERRIDE_DYNAMIC_RELOCATION':
        """
        Creates an IMAGE_FUNCTION_OVERRIDE_DYNAMIC_RELOCATION object from the raw data
        :param raw_data: raw data of the IMAGE_FUNCTION_OVERRIDE_DYNAMIC_RELOCATION
        :return: IMAGE_FUNCTION_OVERRIDE_DYNAMIC_RELOCATION object
        """
        fo_dyn_reloc = cls()
        fo_dyn_reloc.original_rva, fo_dyn_reloc.bdd_offset, fo_dyn_reloc.rva_size, fo_dyn_reloc.base_reloc_size = \
            struct.unpack('<IIII', raw_data[:fo_dyn_reloc.sizeof])
        fo_dyn_reloc.total_size = fo_dyn_reloc.sizeof + fo_dyn_reloc.rva_size + fo_dyn_reloc.base_reloc_size
        
        fo_dyn_reloc.rva_list = []
        fo_dyn_reloc.base_relocations = []
        rva_list_data = raw_data[fo_dyn_reloc.sizeof:fo_dyn_reloc.sizeof + fo_dyn_reloc.rva_size]
        if fo_dyn_reloc.rva_size > 0:
            fo_dyn_reloc.rva_list = list(struct.unpack('<' + 'I' * (fo_dyn_reloc.rva_size // 4), rva_list_data))

        idx = 0
        reloc_data = raw_data[fo_dyn_reloc.sizeof + fo_dyn_reloc.rva_size:]
        while idx <= fo_dyn_reloc.base_reloc_size - IMAGE_BASE_RELOCATION.sizeof:
            reloc = IMAGE_BASE_RELOCATION.from_bytes(reloc_data[idx:])
            idx += reloc.size_of_block
            fo_dyn_reloc.base_relocations.append(reloc)

        return fo_dyn_reloc
    
    @classmethod
    def from_data(cls, original_rva: int, bdd_offset: int, rva_list: List[int], base_relocations: List[IMAGE_BASE_RELOCATION]) -> 'IMAGE_FUNCTION_OVERRIDE_DYNAMIC_RELOCATION':
        """
        Creates an IMAGE_FUNCTION_OVERRIDE_DYNAMIC_RELOCATION object from the given data
        :param virtual_address: virtual address of the base relocation
        :param type_offsets: list of type offsets
        :return: IMAGE_FUNCTION_OVERRIDE_DYNAMIC_RELOCATION object
        """
        fo_dyn_reloc = cls()
        fo_dyn_reloc.original_rva = original_rva
        fo_dyn_reloc.bdd_offset = bdd_offset
        fo_dyn_reloc.rva_list = rva_list
        fo_dyn_reloc.rva_size = len(rva_list) * 4
        fo_dyn_reloc.base_relocations = base_relocations
        fo_dyn_reloc.base_reloc_size = sum([reloc.size_of_block for reloc in base_relocations])
        return fo_dyn_reloc
    
    def __repr__(self) -> str:
        return f'Original RVA: {hex(self.original_rva)} | BDD Offset: {self.bdd_offset} | ' \
               f'RVA Array Size: {self.rva_size} | Base Relocation Size: {self.base_reloc_size} | ' \
               f'RVA Array: {self.rva_list}\n' \
               f'Relocations Info: {self.base_relocations}'
    
    def dump(self) -> bytearray:
        data = bytearray(struct.pack('<IIII', self.original_rva, self.bdd_offset, self.rva_size, self.base_reloc_size))
        data += bytearray(struct.pack('<' + 'I' * len(self.rva_list), *self.rva_list))
        for base_relocation in self.base_relocations:
            data += base_relocation.dump()
        return data


class IMAGE_FUNCTION_OVERRIDE_HEADER:
    sizeof = 4

    def __init__(self):
        self.func_override_size: int = None
        self.func_override_info: List[IMAGE_FUNCTION_OVERRIDE_DYNAMIC_RELOCATION] = []
        self.bdd_info: IMAGE_BDD_INFO = None

    @classmethod
    def from_bytes(cls, raw_data: bytes) -> 'IMAGE_FUNCTION_OVERRIDE_HEADER':
        """
        Creates an IMAGE_FUNCTION_OVERRIDE_HEADER object from the raw data
        :param raw_data: raw data of the IMAGE_FUNCTION_OVERRIDE_HEADER
        :return: IMAGE_FUNCTION_OVERRIDE_HEADER object
        """
        header = cls()
        header.func_override_size = struct.unpack('<I', raw_data[:header.sizeof])[0]

        offset = 0
        fodr_data = raw_data[header.sizeof:header.sizeof + header.func_override_size]
        header.func_override_info = []
        while offset < header.func_override_size:
            ifodr_entry = IMAGE_FUNCTION_OVERRIDE_DYNAMIC_RELOCATION.from_bytes(fodr_data[offset:])
            header.func_override_info.append(ifodr_entry)
            offset += ifodr_entry.sizeof + ifodr_entry.base_reloc_size + ifodr_entry.rva_size

        bdd_info_data = raw_data[header.sizeof + header.func_override_size:]
        header.bdd_info = IMAGE_BDD_INFO.from_bytes(bdd_info_data)
        return header
    

    @classmethod
    def from_data(cls, func_override_info: List[IMAGE_FUNCTION_OVERRIDE_DYNAMIC_RELOCATION]) -> 'IMAGE_FUNCTION_OVERRIDE_HEADER':
        """
        Creates an IMAGE_FUNCTION_OVERRIDE_HEADER object from the given data
        :param virtual_address: virtual address of the base relocation
        :param type_offsets: list of type offsets
        :return: IMAGE_FUNCTION_OVERRIDE_HEADER object
        """
        header = cls()
        header.func_override_size = sum([fo_reloc.total_size for fo_reloc in func_override_info])
        header.func_override_info = func_override_info
        return header

    def __repr__(self) -> str:
        return f'FunctionOverrideSize: {self.func_override_size}\n' \
               f'Function Override Dynamic Relocations: {self.func_override_info}\n' \
               f'BDD Info: {self.bdd_info}'

    def dump(self) -> bytearray:
        data = bytearray(struct.pack('<I', self.func_override_size))
        for func_override_info in self.func_override_info:
            data += func_override_info.dump()
        data += self.bdd_info.dump()
        return data


class IMAGE_BDD_DYNAMIC_RELOCATION:
    sizeof = 8

    def __init__(self):
        self.left: int = None
        self.right: int = None
        self.value: int = None

    @classmethod
    def from_bytes(cls, raw_data: bytes) -> 'IMAGE_BDD_DYNAMIC_RELOCATION':
        """
        Creates an IMAGE_BDD_DYNAMIC_RELOCATION object from the raw data
        :param raw_data: raw data of the IMAGE_BDD_DYNAMIC_RELOCATION
        :return: IMAGE_BDD_DYNAMIC_RELOCATION object
        """
        bdd_dynamic_reloc = cls()
        bdd_dynamic_reloc.left, bdd_dynamic_reloc.right, bdd_dynamic_reloc.value = \
            struct.unpack('<HHI', raw_data[:bdd_dynamic_reloc.sizeof])
        return bdd_dynamic_reloc
    
    @classmethod
    def from_data(cls, left, right, value):
        """
        Creates an IMAGE_FUNCTION_OVERRIDE_HEADER object from the given data
        :param virtual_address: virtual address of the base relocation
        :param type_offsets: list of type offsets
        :return: IMAGE_FUNCTION_OVERRIDE_HEADER object
        """
        bdd_reloc = cls()
        bdd_reloc.left, bdd_reloc.right, bdd_reloc.value = left, right, value
        return bdd_reloc
    
    def __repr__(self) -> str:
        return f'Left: {self.left} | Right: {self.right} | ' \
               f'Value: {hex(self.value)}'
    
    def dump(self) -> bytearray:
        return bytearray(struct.pack('<HHI', self.left, self.right, self.value))
    

class IMAGE_BDD_INFO:
    sizeof = 8

    def __init__(self):
        self.version: int = None
        self.bdd_size: int = None
        self.bdd_nodes_list: List[IMAGE_BDD_DYNAMIC_RELOCATION] = None

    @classmethod
    def from_bytes(cls, raw_data: bytes) -> 'IMAGE_BDD_INFO':
        """
        Creates an IMAGE_BDD_INFO object from the raw data
        :param raw_data: raw data of the IMAGE_BDD_INFO
        :return: IMAGE_BDD_INFO object
        """
        bdd_info = cls()
        bdd_info.version, bdd_info.bdd_size = struct.unpack('<II', raw_data[:bdd_info.sizeof])
        bdd_info.bdd_nodes_list = []

        idx = 0
        bdd_nodes_data = raw_data[bdd_info.sizeof:]
        while idx < bdd_info.bdd_size:
            bdd_info.bdd_nodes_list.append(IMAGE_BDD_DYNAMIC_RELOCATION.from_bytes(bdd_nodes_data[idx:idx+IMAGE_BDD_DYNAMIC_RELOCATION.sizeof]))
            idx += IMAGE_BDD_DYNAMIC_RELOCATION.sizeof
        return bdd_info
    
    @classmethod
    def from_data(cls, version: int, bdd_nodes_list: List[IMAGE_BDD_DYNAMIC_RELOCATION]) -> 'IMAGE_BDD_INFO':
        """
        Creates an IMAGE_FUNCTION_OVERRIDE_HEADER object from the given data
        :param virtual_address: virtual address of the base relocation
        :param type_offsets: list of type offsets
        :return: IMAGE_FUNCTION_OVERRIDE_HEADER object
        """
        bdd_info = cls()
        bdd_info.version = version
        bdd_info.bdd_size = len(bdd_nodes_list) * IMAGE_BDD_DYNAMIC_RELOCATION.sizeof
        bdd_info.bdd_nodes_list = bdd_nodes_list
        return bdd_info
    
    def __repr__(self) -> str:
        return f'Version: {self.version} | BDD Size: {self.bdd_size} \n' \
               f'BDD Nodes: {self.bdd_nodes_list}'

    def dump(self) -> bytearray:
        data = bytearray(struct.pack('<II', self.version, self.bdd_size))
        for node in self.bdd_nodes_list:
            data += node.dump()
        return data
        
