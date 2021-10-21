# Welcome to our PrintNightmare exploit walkthrough project page.
This is our final project for the OKU 2105 Fullstack Academy Cybersecurity course.
We hope we educate you on this exploit and how to mitigate it.

This project centers on CVE-2021-1675, also known as the original zero-day exploit "PrintNightmare". There have been subsequent exploits related to this but we have a focus just on CVE-2021-1675.

# Background
What even is "PrintNightmare"?
PrintNightmare is the name given to CVE-2021-1675, which is a privilige escalation bug found on Windows environments in the print spooler service. The concern is that authenticated users can admin rights via privilege escalation and can even perform remote code execution (RCE) through signed and unsigned loaded drivers to cause havoc in enterprise environments.

# Detection


# Isolation and Recovery


# Sources
https://blog.talosintelligence.com/2021/07/printnightmare-coverage.html
