    chaisneau@chaisneau:~/Documents/42/projects/42woodyWoodpacker$ objdump -D resources/sample64 | tail -f -n 20
    0000000000000000 <.comment>:
      0:   47                      rex.RXB
      1:   43                      rex.XB
      2:   43 3a 20                rex.XB cmp (%r8),%spl
      5:   28 55 62                sub    %dl,0x62(%rbp)
      8:   75 6e                   jne    78 <__abi_tag-0x314>
      a:   74 75                   je     81 <__abi_tag-0x30b>
      c:   20 31                   and    %dh,(%rcx)
      e:   33 2e                   xor    (%rsi),%ebp
      10:   33 2e                   xor    (%rsi),%ebp
      12:   30 2d 36 75 62 75       xor    %ch,0x75627536(%rip)        # 7562754e <_end+0x75623536>
      18:   6e                      outsb  %ds:(%rsi),(%dx)
      19:   74 75                   je     90 <__abi_tag-0x2fc>
      1b:   32 7e 32                xor    0x32(%rsi),%bh
      1e:   34 2e                   xor    $0x2e,%al
      20:   30 34 29                xor    %dh,(%rcx,%rbp,1)
      23:   20 31                   and    %dh,(%rcx)
      25:   33 2e                   xor    (%rsi),%ebp
      27:   33 2e                   xor    (%rsi),%ebp
      29:   30 00                   xor    %al,(%rax)
    chaisneau@chaisneau:~/Documents/42/projects/42woodyWoodpacker$ objdump -D woody | tail -f -n 20

    woody:     file format elf64-x86-64


On the original resources/sample64, the ELF still has its section table, so objdump -D can walk to the final section (.comment) and you see the last 20 decoded bytes there.

Our packed woody zeroes e_shoff, e_shnum, and e_shstrndx, so the ELF has no section headers left. objdump -D relies on those to know what to disassemble; with none present it just prints the file header and nothing else. That’s why the second command shows only the banner line. If you want to inspect the stub you’d need tools that operate from program headers (e.g. objdump --disassemble --section .text before stripping, or ndisasm/gdb) or keep the section table.