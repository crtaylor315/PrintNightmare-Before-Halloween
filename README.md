# Welcome to our PrintNightmare exploit walkthrough project page.
This is our final project for the OKU 2105 Fullstack Academy Cybersecurity course.
We hope we educate you on this exploit and how to mitigate it.

This project centers on CVE-2021-1675, also known as the original zero-day exploit "PrintNightmare". There have been subsequent exploits related to this but we have a focus just on CVE-2021-1675.

# Background
What even is "PrintNightmare"?
PrintNightmare is the name given to CVE-2021-1675 (CVSS 9.3 (critical)), which is a privilige escalation bug found on Windows environments in the print spooler service. The concern is that authenticated users can admin rights via privilege escalation and can even perform remote code execution (RCE) through signed and unsigned loaded drivers to cause havoc in enterprise environments. This exploit was initially patched by Microsoft on June 8, 2021 and has been patched several times; however, rumor is that this exploit is still doable in Windows environments.

# Detection


# Isolation and Recovery


# Sources
https://blog.talosintelligence.com/2021/07/printnightmare-coverage.html ;
https://www.cvedetails.com/cve-details.php?t=1&cve_id=CVE-2021-1675 ;
https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-1675