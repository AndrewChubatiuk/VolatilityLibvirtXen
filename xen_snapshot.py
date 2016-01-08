import volatility.obj as obj
import volatility.addrspace as addrspace

# XEN snapshot Magic
LIBVIRT_MAGIC = "libvirt-xml\n \0 \r"
XL_MAGIC = "Xen saved domain, xl format\n \0 \r"

#Following are tags in the snapshot
XC_SAVE_ID_ENABLE_VERIFY_MODE           = -1
XC_SAVE_ID_VCPU_INFO                    = -2
XC_SAVE_ID_HVM_IDENT_PT                 = -3
XC_SAVE_ID_HVM_VM86_TSS                 = -4
XC_SAVE_ID_TMEM                         = -5
XC_SAVE_ID_TMEM_EXTRA                   = -6
XC_SAVE_ID_TSC_INFO                     = -7
XC_SAVE_ID_HVM_CONSOLE_PFN              = -8
XC_SAVE_ID_LAST_CHECKPOINT              = -9
XC_SAVE_ID_HVM_ACPI_IOPORTS_LOCATION    = -10
XC_SAVE_ID_HVM_VIRIDIAN                 = -11
XC_SAVE_ID_COMPRESSED_DATA              = -12
XC_SAVE_ID_ENABLE_COMPRESSION           = -13
XC_SAVE_ID_HVM_GENERATION_ID_ADDR       = -14
XC_SAVE_ID_HVM_PAGING_RING_PFN          = -15
XC_SAVE_ID_HVM_ACCESS_RING_PFN          = -16
XC_SAVE_ID_HVM_SHARING_RING_PFN         = -17
XC_SAVE_ID_TOOLSTACK                    = -18

## Xen PFN info
XEN_DOMCTL_PFINFO_LTAB_SHIFT    = 28
XEN_DOMCTL_PFINFO_NOTAB         = (0x0 << 28)
XEN_DOMCTL_PFINFO_XTAB          = (0xf << 28)
XEN_DOMCTL_PFINFO_XALLOC        = (0xe << 28)
XEN_DOMCTL_PFINFO_BROKEN        = (0xd << 28)
XEN_DOMCTL_PFINFO_LTAB_MASK     = (0xf << 28)

class XEN_HEADER(obj.CType):
    @property
    def HeaderSize(self):
        return self.struct_size

class XenModification(obj.ProfileModification):
    def modification(self, profile):
        profile.vtypes.update({
            'LIBVIRT_HEADER' : [ 64, {
                'magic' : [ 0, ['String', dict(length = 16)]],
                'version' : [ 16, ['unsigned int']],
                'xml_len' : [ 20, ['unsigned int']],
                'unused' : [ 24, ['unsigned int', dict(length = 10)]],
            }]
        })
        profile.object_classes.update({
            'LIBVIRT_HEADER': XEN_HEADER
        })
        profile.vtypes.update({
            'XL_HEADER' : [ 48, {
                'magic' : [ 0, ['String', dict(length = 32)]],
                'byte_order' : [ 32, ['unsigned int']],
                'mandatofy_flag' : [ 36, ['unsigned int']],
                'opt_flag' : [ 40, ['unsigned int']],
                'opt_data_len' : [ 44, ['unsigned int']],
            }],
        })
        profile.object_classes.update({
            'XL_HEADER': XEN_HEADER
        })

class LibvirtXenSnapshot(addrspace.AbstractRunBasedMemory):

    def __init__(self, base, config, **kwargs):
        self.as_assert(base, "No base Address Space")
        addrspace.AbstractRunBasedMemory.__init__(self, base, config, **kwargs)
        self.libvirt_header = obj.Object("LIBVIRT_HEADER", offset = 0, vm = base)
        self.xl_header = obj.Object("XL_HEADER", offset = 0, vm = base)
        self.offset = 0
        self.PAGE_SIZE  = 4096
        self.PAGE_SHIFT = 12
        self.offsets = {}
        self.xen_vm_max_pfn = 0
        if self.libvirt_header.magic == LIBVIRT_MAGIC:
            self.as_assert(self.libvirt_header.magic == LIBVIRT_MAGIC, "Libvirt Header Mismatch")
            self.offset += self.libvirt_header.xml_len + self.libvirt_header.HeaderSize
        elif self.xl_header.magic == XL_MAGIC:
            self.as_assert(self.xl_header.magic == XL_MAGIC, "XL Xen Header Mismatch")
            self.offset += self.xl_header.HeaderSize + self.xl_header.opt_data_len
        else:
            self.as_assert(self.xl_header.magic == XL_MAGIC, "Xen Header Mismatch")
        p2m_size = obj.Object("unsigned long", offset = self.offset, vm = base)
        self.offset += p2m_size.size()
        while True:
            count = obj.Object("int", self.offset, base)
            self.offset += count.size()
            if count == 0:
                break
            elif count == XC_SAVE_ID_HVM_IDENT_PT or count == XC_SAVE_ID_HVM_VM86_TSS or \
                count == XC_SAVE_ID_HVM_CONSOLE_PFN or count == XC_SAVE_ID_HVM_VIRIDIAN or \
                count == XC_SAVE_ID_HVM_ACPI_IOPORTS_LOCATION or count == XC_SAVE_ID_VCPU_INFO:
                self.offset += 12
            elif count == XC_SAVE_ID_TMEM or count == XC_SAVE_ID_TMEM_EXTRA:
                print ("In tmem_ID Not implemented")
                raise IOError
            elif count == XC_SAVE_ID_TSC_INFO:
                self.offset += 20
            else:
                pfn_array = obj.Object(
                    theType = 'Array', 
                    offset = self.offset, 
                    vm = base, 
                    targetType = 'unsigned long', 
                    count = count
                )
                self.offset += pfn_array.size()
                for x in pfn_array:
                    if self.is_frame_valid(x):
                        pfnno = (x & ~XEN_DOMCTL_PFINFO_LTAB_MASK)
                        self.offsets[pfnno] = self.offset
                        self.offset += self.PAGE_SIZE
                        self.update_max_physical_frame_number(pfnno)
        self.runs.append((0, 0, (self.xen_vm_max_pfn + 1) << self.PAGE_SHIFT)) 
    
    def is_frame_valid(self, x):
        if  ((x & XEN_DOMCTL_PFINFO_LTAB_MASK == XEN_DOMCTL_PFINFO_XTAB) or
             (x & XEN_DOMCTL_PFINFO_LTAB_MASK == XEN_DOMCTL_PFINFO_XALLOC) or
             (x & XEN_DOMCTL_PFINFO_LTAB_MASK == XEN_DOMCTL_PFINFO_BROKEN)):
            return False
        return True

    def update_max_physical_frame_number(self, pfn):
        borders = [(983040, 984063), (1032192, 1032206), (1044475, 1044479)]
        max_value = max([pfn for b in borders if pfn < b[0] or pfn > b[1]])
        self.xen_vm_max_pfn = max_value if max_value > self.xen_vm_max_pfn else self.xen_vm_max_pfn
 
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
  
    def zread(self, address, length):
        return self.read(address, length)
