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
        self.xen_mem_offset = 0
        self.pfn_offsets = {}
        self.xen_vm_max_pfn = 0
        shdrs = list(elf.section_headers())
        offset = shdrs[2].sh_offset
        note = obj.Object("elf64_note", offset, vm = base)
        offset += XEN_ELFNOTE_DESC_SIZE
        note_dhead = obj.Object("elf64_note", offset, vm = base)
        if note_dhead.n_type != XEN_ELFNOTE_DUMPCORE_HEADER:
            return
        offset += XEN_ELFNOTE_DESC_SIZE     
        hdr_desc = obj.Object("XEN_ELF_HEADER_DESC", offset, vm = base)
        if hdr_desc != None:
            self.PAGE_SIZE = hdr_desc.xch_page_size
            self.PAGE_SHIFT = int(math.log(self.PAGE_SIZE, 2))
            self.xen_vm_max_pfn = hdr_desc.xch_nr_pages 
        self.xen_mem_offset = shdrs[5].sh_offset 
        pfn_offset = shdrs[6].sh_offset
        page_offset = self.xen_mem_offset 
        while pfn_offset < (shdrs[6].sh_offset + shdrs[6].sh_size):
            pfnno = int(obj.Object("unsigned long long", pfn_offset, vm=base))
            self.pfn_offsets[pfnno] = page_offset
            pfn_offset += 8
            page_offset += self.PAGE_SIZE
        max_memory_len = (self.xen_vm_max_pfn + 1) << self.PAGE_SHIFT
        
    def is_valid_address(self, phys_addr):
        pfn = phys_addr >> self.PAGE_SHIFT
        return not pfn > self.xen_vm_max_pfn
    
    def get_addr(self, addr):
        pfn = addr >> self.PAGE_SHIFT      
        try:
            return (self.pfn_offsets[pfn] + addr % self.PAGE_SIZE) if self.pfn_offsets[pfn] else None
        except:
            return None

    def read(self, addr, length):
        return self.zread(addr, length)

    def zread(self, addr, length):
        first_block = 0x1000 - addr % 0x1000
        full_blocks = ((length + addr % 0x1000) / 0x1000) - 1
        left_over = (length + addr) % 0x1000
        pfn = addr >> self.PAGE_SHIFT
        if pfn > self.xen_vm_max_pfn:
            raise IOError
        baddr = self.get_addr(addr)
        if baddr == None:
            if length < first_block:
                return '\0' * length
            stuff_read = '\0' * first_block
        else:
            if length < first_block:
                return self.base.read(baddr, length)
            stuff_read = self.base.read(baddr, first_block)
        new_addr = addr + first_block
        for _ in range(full_blocks):
            baddr = self.get_addr(new_addr)
            if baddr == None:
                stuff_read = stuff_read + '\0' * 0x1000
            else:
                stuff_read = stuff_read + self.base.read(baddr, 0x1000)
            new_addr = new_addr + 0x1000
        if left_over > 0:
            baddr = self.get_addr(new_addr)
            if baddr == None:
                stuff_read = stuff_read + '\0' * left_over
            else:
                stuff_read = stuff_read + self.base.read(baddr, left_over)
        return stuff_read
