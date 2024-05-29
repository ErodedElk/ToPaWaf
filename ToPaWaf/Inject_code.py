recover_illgechar=f"""
            push rdx
            push rsi
            mov rax,0
            syscall
            mov rdx,rax
            mov rdi,0
            xor rax,rax
        stt:
            cmp rdi,rdx
            je end
            mov al,byte ptr [rsi+rdi]
            cmp rax,128
            jae erase
            cmp rax,31
            jbe erase
            jmp noop

        erase:
            mov byte ptr [rsi+rdi],0
        noop:
            add rdi,1
            jmp stt
            
        end:
            mov rax,rdx
            pop rsi
            pop rdx
            ret
        """

read_hook=f"""
            push rbp
            mov rbp,rsp
            mov r9,rdi
            xor rdi,rdi
        save_loop:
            cmp rdi,rdx
            jae save_end
            mov rax,qword ptr [rsi+rdi]
            push rax
            add rdi,8
            jmp save_loop
        save_end:
            mov rdi,r9
            mov rax,0
            syscall
            mov rdx,rax
             xor rdi,rdi
            add rsi,0xf
            and rsi, 0xFFFFFFFFFFFFFFF0 
            lea r8,{{cmp_addr}}
            mov r8, qword ptr[r8]
            shr r8,24
            shl r8,24
        stt:
            cmp rdi,rdx
            jae end
            mov rax,qword ptr [rsi+rdi]
            shr rax,48
            cmp rax,0
            ja noop
            mov rax,qword ptr [rsi+rdi]
            cmp rax,r8
            ja erase
            jmp noop
        erase:
            mov rax,rbp
            sub rax,rdi
            sub rax,8
            mov rax,qword ptr [rax]
            mov qword ptr [rsi+rdi],rax
        noop:
            add rdi,8
            jmp stt
        end:
            mov rax,rdx
            leave
            ret
        """