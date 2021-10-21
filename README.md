# Welcome to our PrintNightmare exploit walkthrough project page.
This is our final project for the OKU 2105 Fullstack Academy Cybersecurity course.
We hope we educate you on this exploit and how to mitigate it.

This project centers on CVE-2021-1675, also known as the original zero-day exploit "PrintNightmare". There have been subsequent exploits related to this but we have a focus just on CVE-2021-1675.

# Background
What even is "PrintNightmare"? <br />
PrintNightmare is the name given to CVE-2021-1675, which is a privilige escalation bug found on Windows environments in the print spooler service which is enabled by default. The CVSS was originally deemed low then escalated to critical (9.3). <br />
The concern is that local authenticated users can obtain admin rights via privilege escalation and remote unauthenticated users can perform remote code execution (RCE) through signed and unsigned loaded drivers to cause havoc in vulnerable enterprise environments. This exploit was initially patched by Microsoft on June 8, 2021 and has been patched several times; however, rumor is that this exploit is still executable in Windows environments.

# Detection


# Mitigation
First, make sure that all security patches have been installed then perform the following workaround. <br />
CISA (Cybersecurity and Infrastructure Security Agency) recommends administrators to disable the print spooler service in Domain Controllers and systems that don't print. “Due to the possibility for exposure, domain controllers and Active Directory admin systems need to have the Print spooler service disabled. The recommended way to do this is using a Group Policy Object.” Admin can also prevent remote print requests by using the Group Policy Object. Local printing will still be available on directly connected devices. 

# Isolation and Recovery
Isolation: Microsoft 


# Sources
https://blog.talosintelligence.com/2021/07/printnightmare-coverage.html <br />
https://www.cvedetails.com/cve-details.php?t=1&cve_id=CVE-2021-1675  <br />
https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-1675 <br />
https://github.com/cube0x0/CVE-2021-1675 <br />
https://www.splunk.com/en_us/blog/security/i-pity-the-spool-detecting-printnightmare-cve-2021-34527.html <br />
https://www.kb.cert.org/vuls/id/383432 <br />
https://docs.microsoft.com/en-us/windows-hardware/drivers/print/printer-driver-isolation <br />
