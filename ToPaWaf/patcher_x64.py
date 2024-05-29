from subprocess import *
import sys, os
from pwn import *
import capstone
# from ToPaWaf.Inject_code import read_hook
from ToPaWaf.Inject_code import recover_illgechar as read_hook
def round_up(value,align):
    if value%align==0:
        return value
    else:
        return value+(align-(value%align))

class ToPaWaf:
    def __init__(self,filename,is_rx=True,code_addr=0):
        self.filename=filename
        self.elf=ELF(filename)
        context.arch = 'amd64'
        self.tr=open(self.filename,"rb+")
        self.is_rx=is_rx
        self.code_addr=code_addr
        # self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        # self.md.detail = True

    def logh(self,key,value):
        log.success(key + '===>' + hex(value))

    def run(self):
        if self.elf.pie == True:
            if self.is_rx:
                self.edit_table_rwx()
                self.patch_pie_elf()
            else:
                if self.code_addr!=0:
                    self.patch_pie_elf_by_addr()
                else:
                    self.code_addr=self.elf.get_section_by_name(".fini").header.sh_addr
                    self.code_addr=round_up(self.code_addr,0x10)
                    self.patch_pie_elf_by_addr()
        else:
            if self.is_rx:
                self.edit_table_rwx()
                self.patch_nopie_elf_partical()
            else:
                if self.code_addr!=0:
                    self.patch_nopie_elf_partical_by_addr()
                else:
                    self.code_addr=self.elf.get_section_by_name(".fini").header.sh_addr
                    self.code_addr=round_up(self.code_addr,0x10)
                    self.patch_nopie_elf_partical_by_addr()
                pass
        self.tr.close()

    def edit_table_rwx(self):
        demo=self.elf.get_section_by_name('.eh_frame')
        self.write_addr=demo.header.sh_addr
        self.section_size=demo.header.sh_size

        program_table_header_start = self.elf.address + self.elf.header.e_phoff
        num_of_program_table_header = self.elf.header.e_phnum
        size_of_program_headers = self.elf.header.e_phentsize

        for i in range(num_of_program_table_header):
            p_type = self.elf.get_segment(i).header.p_type
            p_flags = self.elf.get_segment(i).header.p_flags
            if p_type == 'PT_LOAD' and p_flags == 4:
                addr=self.elf.vaddr_to_offset(program_table_header_start + i * size_of_program_headers + 4)
                self.tr.seek(addr)
                self.tr.write(p32(5))
                # self.elf.write(, p32(7))
                print('edit program_table_element[' + str(i) + '].p_flags===>r_x')

    def patch_pie_elf(self):
        print("[*] Start Patch Pie")
        eh_frame_addr = self.elf.get_section_by_name('.eh_frame').header.sh_addr
        self.eh_frame_addr=eh_frame_addr

        rela_plt = self.elf.get_section_by_name('.rela.plt')

        dyn_sec=self.elf.get_section_by_name('.dynamic')

        self.rela_plt_addr=rela_plt.header.sh_addr
        self.rela_plt_size=rela_plt.header.sh_size
        

        DT_RELASZ_addr=dyn_sec.header.sh_addr+0x120+8-0x40
        DT_RELASZ_Size=u64(self.elf.read(DT_RELASZ_addr, 8))

        res_RELASZ_Size=DT_RELASZ_Size+0x18

        offset=eh_frame_addr+0x3b-0x18-self.elf.get_section_by_name('.got').header.sh_addr
        if offset>0:
            inject_code=read_hook.replace("{cmp_addr}",f"[rip-{str(offset)}]")
        else:
            offset=-offset
            inject_code=read_hook.replace("{cmp_addr}",f"[rip+{str(offset)}]")
        inject_sc=asm(inject_code)
        save_backup=self.elf.read(eh_frame_addr,len(inject_sc))
        self.save_backup=save_backup

        DT_RELASZ_addr=self.elf.vaddr_to_offset(DT_RELASZ_addr)
        
        target_addr=self.rela_plt_addr
        target_addr=self.elf.vaddr_to_offset(target_addr)
        target_addr=target_addr+self.rela_plt_size

        self.elf.close()

        tr=self.tr
        payload=p64(self.elf.got["read"])+p64(8)+p64(eh_frame_addr)
        print(f"[*] {hex(target_addr)} ----> {payload.hex()}")
        tr.seek(target_addr)
        tr.write(payload)

        print(f"[*] {hex(DT_RELASZ_addr)} ----> {p64(res_RELASZ_Size).hex()}")
        tr.seek(DT_RELASZ_addr)
        tr.write(p64(res_RELASZ_Size))

        print(f"[*] {hex(eh_frame_addr)} ----> {inject_sc.hex()}")
        tr.seek(eh_frame_addr)
        tr.write((inject_sc))
    
    def patch_pie_elf_by_addr(self):
        print("[*] Start Patch Pie")
        eh_frame_addr = self.elf.get_section_by_name('.eh_frame').header.sh_addr
        self.eh_frame_addr=eh_frame_addr

        rela_plt = self.elf.get_section_by_name('.rela.plt')

        dyn_sec=self.elf.get_section_by_name('.dynamic')


        self.rela_plt_addr=rela_plt.header.sh_addr
        self.rela_plt_size=rela_plt.header.sh_size
        

        DT_RELASZ_addr=dyn_sec.header.sh_addr+0x120+8-0x40
        DT_RELASZ_Size=u64(self.elf.read(DT_RELASZ_addr, 8))

        res_RELASZ_Size=DT_RELASZ_Size+0x18

        offset=self.code_addr+0x3b-0x18-self.elf.get_section_by_name('.got').header.sh_addr
        if offset>0:
            inject_code=read_hook.replace("{cmp_addr}",f"[rip-{str(offset)}]")
        else:
            offset=-offset
            inject_code=read_hook.replace("{cmp_addr}",f"[rip+{str(offset)}]")
        inject_sc=asm(inject_code)
        save_backup=self.elf.read(eh_frame_addr,len(inject_sc))
        self.save_backup=save_backup

        DT_RELASZ_addr=self.elf.vaddr_to_offset(DT_RELASZ_addr)
        
        target_addr=self.rela_plt_addr
        target_addr=self.elf.vaddr_to_offset(target_addr)
        target_addr=target_addr+self.rela_plt_size

        self.elf.close()

        tr=self.tr
        payload=p64(self.elf.got["read"])+p64(8)+p64(self.code_addr)
        print(f"[*] {hex(target_addr)} ----> {payload.hex()}")
        tr.seek(target_addr)
        tr.write(payload)

        print(f"[*] {hex(DT_RELASZ_addr)} ----> {p64(res_RELASZ_Size).hex()}")
        tr.seek(DT_RELASZ_addr)
        tr.write(p64(res_RELASZ_Size))
        
        print(f"[*] {hex(eh_frame_addr)} ----> {inject_sc.hex()}")
        tr.seek(self.elf.vaddr_to_offset(self.code_addr))
        tr.write((inject_sc))

    def patch_nopie_elf_partical(self):
        print("[*] Start Patch No-Pie")
        eh_frame_addr = self.elf.get_section_by_name('.eh_frame').header.sh_addr
        self.eh_frame_addr=eh_frame_addr

        rela_plt = self.elf.get_section_by_name('.rela.plt')

        dyn_sec=self.elf.get_section_by_name('.dynamic')

        self.rela_plt_addr=rela_plt.header.sh_addr
        self.rela_plt_size=rela_plt.header.sh_size
        
        DT_RELASZ_addr1=dyn_sec.header.sh_addr+0x120+8
        DT_RELASZ_addr2=dyn_sec.header.sh_addr+0x120+8-0x40
        DT_RELASZ_Size1=u64(self.elf.read(DT_RELASZ_addr1, 8))
        DT_RELASZ_Size2=u64(self.elf.read(DT_RELASZ_addr2, 8))

        res_RELASZ_Size=DT_RELASZ_Size1+DT_RELASZ_Size2+0x18

        offset=eh_frame_addr+0x3b-0x18-self.elf.get_section_by_name('.got').header.sh_addr
        if offset>0:
            inject_code=read_hook.replace("{cmp_addr}",f"[rip-{str(offset)}]")
        else:
            offset=-offset
            inject_code=read_hook.replace("{cmp_addr}",f"[rip+{str(offset)}]")
        inject_sc=asm(inject_code)
        save_backup=self.elf.read(eh_frame_addr,len(inject_sc))
        self.save_backup=save_backup

        DT_RELASZ_addr=self.elf.vaddr_to_offset(DT_RELASZ_addr1)
        
        target_addr=self.rela_plt_addr
        target_addr=self.elf.vaddr_to_offset(target_addr)
        target_addr=target_addr+self.rela_plt_size

        self.elf.close()

        tr=self.tr
        payload=p64(self.elf.got["read"])+p64(8)+p64(eh_frame_addr)
        print(f"[*] {hex(target_addr)} ----> {payload.hex()}")
        tr.seek(target_addr)
        tr.write(payload)

        print(f"[*] {hex(DT_RELASZ_addr)} ----> {p64(res_RELASZ_Size).hex()}")
        tr.seek(DT_RELASZ_addr)
        tr.write(p64(res_RELASZ_Size))

        print(f"[*] {hex(eh_frame_addr)} ----> {inject_sc.hex()}")
        tr.seek(self.elf.vaddr_to_offset(eh_frame_addr))
        tr.write((inject_sc))

    def patch_nopie_elf_partical_by_addr(self):
        print("[*] Start Patch No-Pie")
        eh_frame_addr = self.elf.get_section_by_name('.eh_frame').header.sh_addr
        self.eh_frame_addr=eh_frame_addr

        rela_plt = self.elf.get_section_by_name('.rela.plt')

        dyn_sec=self.elf.get_section_by_name('.dynamic')

        self.rela_plt_addr=rela_plt.header.sh_addr
        self.rela_plt_size=rela_plt.header.sh_size
        
        DT_RELASZ_addr1=dyn_sec.header.sh_addr+0x120+8
        DT_RELASZ_addr2=dyn_sec.header.sh_addr+0x120+8-0x40
        DT_RELASZ_Size1=u64(self.elf.read(DT_RELASZ_addr1, 8))
        DT_RELASZ_Size2=u64(self.elf.read(DT_RELASZ_addr2, 8))

        res_RELASZ_Size=DT_RELASZ_Size1+DT_RELASZ_Size2+0x18

        offset=self.code_addr+0x3b-0x18-self.elf.get_section_by_name('.got').header.sh_addr
        if offset>0:
            inject_code=read_hook.replace("{cmp_addr}",f"[rip-{str(offset)}]")
        else:
            offset=-offset
            inject_code=read_hook.replace("{cmp_addr}",f"[rip+{str(offset)}]")
        inject_sc=asm(inject_code)

        DT_RELASZ_addr=self.elf.vaddr_to_offset(DT_RELASZ_addr1)
        
        target_addr=self.rela_plt_addr
        target_addr=self.elf.vaddr_to_offset(target_addr)
        target_addr=target_addr+self.rela_plt_size

        self.elf.close()

        tr=self.tr
        payload=p64(self.elf.got["read"])+p64(8)+p64(self.code_addr)
        print(f"[*] {hex(target_addr)} ----> {payload.hex()}")
        tr.seek(target_addr)
        tr.write(payload)

        print(f"[*] {hex(DT_RELASZ_addr)} ----> {p64(res_RELASZ_Size).hex()}")
        tr.seek(DT_RELASZ_addr)
        tr.write(p64(res_RELASZ_Size))

        print(f"[*] {hex(self.code_addr)} ----> {inject_sc.hex()}")
        tr.seek(self.elf.vaddr_to_offset(self.code_addr))
        tr.write((inject_sc))
