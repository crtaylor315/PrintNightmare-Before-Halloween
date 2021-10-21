# Welcome to our PrintNightmare exploit walkthrough project page.
This is our final project for the OKU 2105 Fullstack Academy Cybersecurity course.
We hope we educate you on this exploit and how to mitigate it.

This project centers on CVE-2021-1675, also known as the original zero-day exploit "PrintNightmare". There have been subsequent exploits related to this but we have a focus just on CVE-2021-1675.

# Background
What even is "PrintNightmare"? <br />
PrintNightmare is the name given to CVE-2021-1675, which is a privilige escalation vulnerability found on Windows environments in the print spooler service. This service is enabled by default on all client and server platforms. Microsoft delayed issuing a patch for the vulneraility for nearly 10 days after it was made public because the CVSS was originally deemed low then was escalated to critical (9.3). <br />
The concern is that local authenticated users can obtain SYSTEM rights via privilege escalation and remote unauthenticated users can perform remote code execution (RCE) through signed and unsigned loaded drivers to cause havoc in vulnerable enterprise environments. The drivers of concern are **RpcAddPrinterDriverEx()** over SMB and **RpcAsyncAddPrinterDriver()** over RPC. <br />
The exploit was initially patched by Microsoft on June 8, 2021 and has been patched several times; however, rumor is that this exploit is still executable in Windows environments.

# Detection
Is your system vulnerable? Here's how to find out: <br />
We can run a scan in the command line using the code provided by Impacket called **rpcdump.py** (located in the code section) to scan for vulnerable hosts. If it returns with a value, the host may be vulnerable to the exploit. <br />

Example: <br />
rpcdump.py @192.168.1.10 | egrep 'MS-RPRN|MS-PAR'

Protocol: [MS-PAR]: Print System Asynchronous Remote Protocol 
Protocol: [MS-RPRN]: Print System Remote Protocol <br />

You can also check for the following values on your machine: <br />
REG QUERY "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint"

HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint
    RestrictDriverInstallationToAdministrators    REG_DWORD    0x0
    NoWarningNoElevationOnInstall    REG_DWORD    0x1 <br />
    
    OR you can use the following Powershell command: <br />
    Get-Service -Name Spooler <br />
    
# Mitigation
First, make sure that all security patches have been installed then perform the following workaround for an added layer of security. <br />
CISA (Cybersecurity and Infrastructure Security Agency) recommends administrators to disable the print spooler service in Domain Controllers and systems that do not print. _“Due to the possibility for exposure, domain controllers and Active Directory admin systems need to have the Print spooler service disabled. The recommended way to do this is using a Group Policy Object.”_ <br />
Admin can also prevent remote print requests by using the Group Policy Object. Local printing will still be available for directly connected devices.

Example: <br />
Stop-Service Spooler
REG ADD  "HKLM\SYSTEM\CurrentControlSet\Services\Spooler"  /v "Start" /t REG_DWORD /d "4" /f <br />

or using the following Powershell commands: <br />
Stop-Service -Name Spooler -Force

Set-Service -Name Spooler -StartupType Disabled <br />

**Make sure to restart the print spooler after it has been disabled**

# Reproduction of the exploit <br />

# Related Links
https://blog.talosintelligence.com/2021/07/printnightmare-coverage.html <br />
https://www.cvedetails.com/cve-details.php?t=1&cve_id=CVE-2021-1675  <br />
https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-1675 <br />
https://github.com/cube0x0/CVE-2021-1675 <br />
https://www.splunk.com/en_us/blog/security/i-pity-the-spool-detecting-printnightmare-cve-2021-34527.html <br />
https://www.kb.cert.org/vuls/id/383432 <br />
https://docs.microsoft.com/en-us/windows-hardware/drivers/print/printer-driver-isolation <br />
