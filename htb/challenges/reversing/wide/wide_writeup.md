# WIDE

## Analyzing the Files

```c
┌──(user㉿kali)-[/media/…/htb/challenges/wide/files]
└─$ unzip WIDE.zip 
Archive:  WIDE.zip
   creating: rev_wide/
[WIDE.zip] rev_wide/wide password: 
  inflating: rev_wide/wide           
  inflating: rev_wide/db.ex
```

```c
┌──(user㉿kali)-[/media/…/challenges/wide/files/rev_wide]
└─$ file wide 
wide: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=13869bb7ce2c22f474b95ba21c9d7e9ff74ecc3f, not stripped
```

```c
┌──(user㉿kali)-[/media/…/challenges/wide/files/rev_wide]
└─$ file db.ex 
db.ex: Matlab v4 mat-file (little endian) , numeric, rows 1835627088, columns 29557
```

```c
┌──(user㉿kali)-[/media/…/challenges/wide/files/rev_wide]
└─$ ./wide
Usage: ./wide db.ex
```

```c
┌──(user㉿kali)-[/media/…/challenges/wide/files/rev_wide]
└─$ ./wide db.ex 
[*] Welcome user: kr4eq4L2$12xb, to the Widely Inflated Dimension Editor [*]
[*]    Serving your pocket dimension storage needs since 14,012.5 B      [*]
[*]                       Displaying Dimensions....                      [*]
[*]       Name       |              Code                |   Encrypted    [*]
[X] Primus           | people breathe variety practice  |                [*]
[X] Cheagaz          | scene control river importance   |                [*]
[X] Byenoovia        | fighting cast it parallel        |                [*]
[X] Cloteprea        | facing motor unusual heavy       |                [*]
[X] Maraqa           | stomach motion sale valuable     |                [*]
[X] Aidor            | feathers stream sides gate       |                [*]
[X] Flaggle Alpha    | admin secret power hidden        |       *        [*]
Which dimension would you like to examine?
```

```c
Which dimension would you like to examine? 6
[X] That entry is encrypted - please enter your WIDE decryption key:
```

```c
┌──(user㉿kali)-[/media/…/challenges/wide/files/rev_wide]
└─$ strings wide 
/lib64/ld-linux-x86-64.so.2
libc.so.6
exit
fopen
ftell
puts
mbstowcs
stdin
printf
strtol
fgets
calloc
fseek
fclose
wcscmp
fread
__cxa_finalize
__libc_start_main
GLIBC_2.2.5
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
AWAVI
AUATL
[]A\A]A^A_
Which dimension would you like to examine? 
That option was invalid.
[X] That entry is encrypted - please enter your WIDE decryption key: 
[X]                          Key was incorrect                           [X]
Usage: %s db.ex
[*] Welcome user: kr4eq4L2$12xb, to the Widely Inflated Dimension Editor [*]
[*]    Serving your pocket dimension storage needs since 14,012.5 B      [*]
[x] There was a problem accessing your database [x]
[*]                       Displaying Dimensions....                      [*]
[*]       Name       |              Code                |   Encrypted    [*]
[X] %-16s | %-32s | %6s%c%7s [*]
;*3$"
GCC: (Ubuntu 7.5.0-3ubuntu1~18.04) 7.5.0
crtstuff.c
deregister_tm_clones
__do_global_dtors_aux
completed.7698
__do_global_dtors_aux_fini_array_entry
frame_dummy
__frame_dummy_init_array_entry
wide.c
__FRAME_END__
__init_array_end
_DYNAMIC
__init_array_start
__GNU_EH_FRAME_HDR
_GLOBAL_OFFSET_TABLE_
__libc_csu_fini
wcscmp@@GLIBC_2.2.5
_ITM_deregisterTMCloneTable
puts@@GLIBC_2.2.5
fread@@GLIBC_2.2.5
stdin@@GLIBC_2.2.5
mbstowcs@@GLIBC_2.2.5
_edata
fclose@@GLIBC_2.2.5
menu
printf@@GLIBC_2.2.5
__libc_start_main@@GLIBC_2.2.5
fgets@@GLIBC_2.2.5
calloc@@GLIBC_2.2.5
__data_start
ftell@@GLIBC_2.2.5
__gmon_start__
strtol@@GLIBC_2.2.5
__dso_handle
_IO_stdin_used
__libc_csu_init
fseek@@GLIBC_2.2.5
__bss_start
main
fopen@@GLIBC_2.2.5
exit@@GLIBC_2.2.5
__TMC_END__
_ITM_registerTMCloneTable
__cxa_finalize@@GLIBC_2.2.5
.symtab
.strtab
.shstrtab
.interp
.note.ABI-tag
.note.gnu.build-id
.gnu.hash
.dynsym
.dynstr
.gnu.version
.gnu.version_r
.rela.dyn
.rela.plt
.init
.plt.got
.text
.fini
.rodata
.eh_frame_hdr
.eh_frame
.init_array
.fini_array
.dynamic
.data
.bss
.comment
```

## Analyzing with Ghidra

Search > For Strings...

```c
CONFLICTS	00101114	s_[X]_That_entry_is_encrypted_-_pl_001010d0	ds "[X] That entry is encrypted - please enter your WIDE decryption key: "	U" sup3rs3cr3tw1d3"	unicode32	68	false
```

| Secret |
| --- |
| sup3rs3cr3tw1d3 |

## Flag

```c
Which dimension would you like to examine? 6
[X] That entry is encrypted - please enter your WIDE decryption key: sup3rs3cr3tw1d3
HTB{som3_str1ng5_4r3_w1d3}
```
