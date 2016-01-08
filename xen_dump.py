import volatility.obj as obj
import volatility.addrspace as addrspace
import math
from ctypes import c_ulonglong

XEN_ELFNOTE_DUMPCORE_NONE = 0x2000000
XEN_ELFNOTE_DUMPCORE_HEADER = 0x2000001
XEN_ELFNOTE_DUMPCORE_XEN_VERSION = 0x2000002
XEN_ELFNOTE_DUMPCORE_FORMAT_VERSION = 0x2000003

XEN_VERSION_DESC_SIZE = 1276
XEN_ELF_HEADER_DESC_SIZE = 32
XEN_FORMAT_VERSION_DESC_SIZE = 8
XEN_ELFNOTE_DESC_SIZE = 16

class XEN_ELF_HEADER_DESC(obj.CType):
    pass
    
class XenElfModification(obj.ProfileModification):
    def modification(self, profile):
        profile.vtypes.update({
            'XEN_ELF_HEADER_DESC' : [ 32, {
                'xch_magic' : [ 0, ['unsigned long long']],
                'xch_nr_cpu' : [ 8, ['unsigned long long']],
                'xch_nr_pages' : [ 16, ['unsigned long long']],
                'xch_page_size' : [ 24, ['unsigned long long']],
            }]})
        profile.object_classes.update({'XEN_ELF_HEADER_DESC': XEN_ELF_HEADER_DESC})
        
class XenCoreDumpElf64(addrspace.AbstractRunBasedMemory):
        
    def __init__(self, base, config, **kwargs):
        self.as_assert(base, "No base Address Space")
        addrspace.AbstractRunBasedMemory.__init__(self, base, config, **kwargs)
        self.as_assert(base.read(0, 6) == '\x7fELF\x02\x01', "ELF64 Header signature invalid")
        elf = obj.Object("elf_hdr", offset = 0, vm=base)
        self.as_assert(str(elf.e_type) == 'ET_CORE', "ELF64 type is not a Core file")
        self.PAGE_SIZE = 0
        self.PAGE_SHIFT = 0
        self.offsets = {}
        self.xen_vm_max_pfn = 0
        shdrs = list(elf.section_headers())
        try:
            offset = shdrs[2].sh_offset + XEN_ELFNOTE_DESC_SIZE
            note = obj.Object("elf64_note", offset, vm = base)
            if note.n_type != XEN_ELFNOTE_DUMPCORE_HEADER:
                return
            offset += XEN_ELFNOTE_DESC_SIZE     
            header_desc = obj.Object("XEN_ELF_HEADER_DESC", offset, vm = base)
            if header_desc != None:
                self.PAGE_SIZE = header_desc.xch_page_size
                self.PAGE_SHIFT = int(math.log(self.PAGE_SIZE, 2))
                self.xen_vm_max_pfn = header_desc.xch_nr_pages 
            page_offset = shdrs[5].sh_offset 
            pfn_offset = shdrs[6].sh_offset
            while pfn_offset < (shdrs[6].sh_offset + shdrs[6].sh_size):
                pfnno = int(obj.Object("unsigned long long", pfn_offset, vm=base))
                self.offsets[pfnno] = page_offset
                pfn_offset += 8
                page_offset += self.PAGE_SIZE
        except:
            pass
        max_memory_len = (self.xen_vm_max_pfn + 1) << self.PAGE_SHIFT

    def is_valid_address(self, physical_address):
        pfn = physical_address >> self.PAGE_SHIFT
        return not pfn > self.xen_vm_max_pfn
    
    def get_address(self, address):
        pfn = address >> self.PAGE_SHIFT
        return self.offsets[pfn] + address % self.PAGE_SIZE if self.offsets[pfn] else None

    def read(self, address, length):
        return self.zread(address, length)
    
    def zread(self, address, length):
        first_block = 0x1000 - address % 0x1000
        full_blocks = ((length + address % 0x1000) / 0x1000) - 1
        left_over = (length + address) % 0x1000
        pfn = address >> self.PAGE_SHIFT
        if pfn > self.xen_vm_max_pfn:
            raise IOError
        baddress = self.get_address(address)
        if length < first_block:
            return self.base.read(baddress, length) if baddress else '\0' * length
        stuff_read = self.base.read(baddress, first_block) if baddress else '\0' * first_block
        baddress = self.get_address(address + first_block)
        for _ in range(full_blocks):
            stuff_read += self.base.read(baddress, 0x1000) if baddress else '\0' * 0x1000
            address += 0x1000
        if left_over > 0:
            stuff_read += self.base.read(baddress, left_over) if baddress else '\0' * left_over
        return stuff_read
