import volatility.obj as obj
import volatility.addrspace as addrspace
import math
from ctypes import c_ulonglong

XEN_ELFNOTE_DUMPCORE_HEADER = 0x2000001
XEN_ELFNOTE_DESC_SIZE = 16

class ELF_HEADER(obj.CType):
    @property
    def HeaderSize(self):
        return self.struct_size
    
class XenElfModification(obj.ProfileModification):
    def modification(self, profile):
        profile.vtypes.update({
            'ELF_HEADER' : [ 32, {
                'xch_magic' : [ 0, ['unsigned long long']],
                'xch_nr_cpu' : [ 8, ['unsigned long long']],
                'xch_nr_pages' : [ 16, ['unsigned long long']],
                'xch_page_size' : [ 24, ['unsigned long long']],
            }]})
        profile.object_classes.update({
            'ELF_HEADER': ELF_HEADER
        })

class XenElfDump(addrspace.AbstractRunBasedMemory):
   
    def __init__(self, base, config, **kwargs):
        self.as_assert(base, "No base Address Space")
        addrspace.AbstractRunBasedMemory.__init__(self, base, config, **kwargs)
        self.as_assert(base.read(0, 6) == '\x7fELF\x02\x01', "ELF64 Header signature invalid")
        elf = obj.Object("elf_hdr", offset = 0, vm = base)
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
            header_desc = obj.Object("ELF_HEADER", offset, vm = base)
            if header_desc != None:
                self.PAGE_SIZE = header_desc.xch_page_size
                self.PAGE_SHIFT = int(math.log(self.PAGE_SIZE, 2))
                self.xen_vm_max_pfn = header_desc.xch_nr_pages 
            page_offset = shdrs[5].sh_offset 
            offset = shdrs[6].sh_offset
            while offset < (shdrs[6].sh_offset + shdrs[6].sh_size):
                pfnno = int(obj.Object("unsigned long long", offset, vm = base))
                self.offsets[pfnno] = page_offset
                offset += 8
                page_offset += self.PAGE_SIZE
        except:
            pass
        self.runs.append((0, 0, (self.xen_vm_max_pfn + 1) << self.PAGE_SHIFT))
        self.as_assert(self.runs, 'ELF error: did not find any LOAD segment with main RAM')

    def is_valid_address(self, phys_addr):
        return not self.address_out_range(phys_addr)
    
    def get_address(self, addr):
        pfn = addr >> self.PAGE_SHIFT
        try:
            return self.offsets[pfn] + addr % self.PAGE_SIZE if self.offsets[pfn] else None
        except:
            return None

    def address_out_range(self, addr):
        return (addr >> self.PAGE_SHIFT) > self.xen_vm_max_pfn
    
    def read(self, addr, length):
        first_block = 0x1000 - addr % 0x1000
        full_blocks = ((length + (addr % 0x1000)) / 0x1000) - 1
        left_over = (length + addr) % 0x1000
        if  self.address_out_range(addr):
            return obj.NoneObject("Could not get base address at " + str(addr))
        baddr = self.get_address(addr)
        if length < first_block:
            return self.base.read(baddr, length) if baddr else '\0'*length
        stuff_read = self.base.read(baddr, first_block) if baddr else '\0' * first_block
        addr += first_block
        for _ in range(0, full_blocks):
            baddr = self.get_address(addr)
            stuff_read += self.base.read(baddr, 0x1000) if baddr else '0'*0X1000
            addr += 0x1000
        if left_over > 0:
            baddr = self.get_address(addr)
            stuff_read += self.base.read(baddr, left_over) if baddr else '0'*left_over
        return stuff_read

    def zread(self, addr, length):
        return self.read(addr, length)
