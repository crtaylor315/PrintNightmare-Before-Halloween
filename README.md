# Welcome to our PrintNightmare exploit Capstone writeup. <br />
This is our final project for the OKU 2105 Fullstack Academy Cybersecurity course. We hope we will educate you on this exploit and how to mitigate it.
This project centers on CVE-2021-1675 + CVE-2021-34527, also known as the zero-day exploit "PrintNightmare". There have been subsequent exploits related to this, but we will focus on CVE-2021-1675 and CVE-2021-34527. <br />

# What even is "PrintNightmare"? <br />
PrintNightmare is the name given to CVE-2021-1675 and CVE-2021-34527, both of which are privilege escalation vulnerabilities found on Windows environments in the print spooler service. This service is enabled by default on all client and server platforms. Microsoft delayed issuing a patch for the vulnerability for nearly 10 days after the vulnerability was made public because the CVSS was originally deemed low then was escalated to critical (9.3).
The concern is that locally authenticated users can obtain SYSTEM rights via privilege escalation and remote unauthenticated users can perform remote code execution (RCE) through signed and unsigned loaded drivers to cause havoc in vulnerable enterprise environments. The drivers of concern are RpcAddPrinterDriverEx() over SMB and RpcAsyncAddPrinterDriver() over RPC.
The exploit was initially patched by Microsoft on June 8, 2021, and has been patched several times; however, the rumor is that this exploit is still executable in Windows environments. <br />

# Detection
Is your system vulnerable? Here's how to find out: <br />
We can run a scan in the command line using the code provided by Impacket called rpcdump.py (located in the code section) to scan for vulnerable hosts. If it returns with a value, the host may be vulnerable to the exploit. <br />
**Detecting and or Recognizing What an Attack Looks Like on a Victim’s OS with the PrintNightMare Exploit.** <br />
Now for the savvy computer advanced user, it’s a no brainer to disable any Windows Print Spooler service but if this is like a foreign language, and by the way it is, then the admin of the computer or cybersecurity blue team can take 6 easy steps to disable the Print Spooler option in your operating system. <br />  1.) In Start Menu run Powershell as an administrator. <br /> 2.) Type and Enter Stop-service -Name Spooler -Force in the command line. <br /> 3.) To block and prevent service from restarting when the system gets rebooted enter the following command Set-Service -Name Spooler -StartupType Disabled. <br /> 4.) Open the Start and search for gpedit.msc. <br /> 5.) Now open computer configuration < Administrative Templates < Printers. When you see Allow Print Spooler to Accept client connections, double click. <br /> 6.) The final step is to select Disabled option and click it. <br /> <br />
The Print Spooler is the middleman between your computer and your printer. Its basic function is to manage print jobs; therefore, it's highly recommended by security professionals to disable this option. There are tools like Semperis’ Directory Services Protector (DPS) that continuously detects and scans systems for red flags or indicators of compromise on an operating system. Some researchers have observed and logged activity for what a compromised system using the PrintNightmare might look like. <br /> The use of malicious DLL files is noted and remote use of SMB share is redirected by the attacker to inject into the memory process of the targeted system and finalizes the attack by loading the DLL in the Print Service Spooler. <br /> Other red flags to look out for: <br /> using Process Explorer, include processes being spawned, error codes of 808 from event source are visible to the victim. <br /> In the event a new printer is added or updated to the system, 316 code generates and the OS will be getting lots of error messages and codes. Other eye-openers to keep an eye open for would be the creation of new DLL files under spool drivers, suspicious activity of spawning processes from Print Service Spooler, any outbound connection originating from child processes relating to Print Spooler services, and Malware detection from Print Spooler path. <br /> Once your machine has been compromised, the attackers may remotely and gradually take over your entire system. This is why it's critical to disable the Print Spooler option if you're using a supported version of Windows to avoid being hacked. <br />
# Damage Control & the Recovery Process Once a System has been Compromised <br />
Once a system has been compromised, it is important to isolate the damage in a safe environment. It is always a good idea to have a backup OS in case it crashes or is targeted. In the case where the entire system is taken over, the best solution is to delete and or erase everything on your hard drive and back it up with your backup copy that was taken before the attack. <br /> If no backup copy is readily available, then unfortunately there is a lesson to be learned-—and sometimes these lessons are hard but well learned. A system restore will be needed from an earlier uncompromised time. <br /> After reinstallation of Microsoft Windows 10 or the newest version has been installed, make sure all security patches are up to date and immediately disable the Print Spooler option. Keeping your Windows OS  updated and patched is a key factor in cybersecurity and is highly recommended by all cybersecurity professionals in the industry. <br /> Often some of us get lazy or simply forget to update our computers but there is an option that can be enabled for automatic updates on system and software which can help keep your machine running and operating with less worry of an attack. <br /> Please note that attackers will always find ways or backdoors to attack the victim(s). <br /> By reinstalling Windows, most software, including printer drivers, will be updated and or patched. <br /> As a rule of thumb: avoid downloading any suspicious or weird links which can be malicious malware, viruses, or bad stuff your OS does not need. <br /> The manufacturer's website has the latest drivers and patches available for public use. The deletion of unnecessary registry keys helps to avoid this specific type of attack. Always scan your computer and use tools to help detect and or protect. <br /> Frequently, run **chkdsk** utility to check for disk errors relating to the Print Spooler service. Make sure to change Spooler recovery options to avoid an automatic restart of software. Also, resetting internet settings can help the system run smoother without interference from Spooler. <br />  If possible, replace the infection printer. These are some steps that can be taken when recovering from PrintNightmare exploit using the print spooler vulnerability. <br />

![image](https://user-images.githubusercontent.com/83483181/138566092-dded20b8-aca8-40e3-b5b5-db49eaaa6350.png)

Example: <br />
rpcdump.py @192.168.1.10 | egrep 'MS-RPRN|MS-PAR'

Protocol: [MS-PAR]: Print System Asynchronous Remote Protocol 
Protocol: [MS-RPRN]: Print System Remote Protocol <br />

You can also check for the following values on your machine: <br />
REG QUERY "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint"

HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint
    RestrictDriverInstallationToAdministrators    REG_DWORD    0x0
    NoWarningNoElevationOnInstall    REG_DWORD    0x1 <br />
    
Or you can use the following Powershell command: <br />
Get-Service -Name Spooler <br />

# Mitigation and Isolation
First, make sure that all security patches have been installed, then perform the following workaround for an added layer of security: <br />
CISA recommends administrators disable the print spooler service in Domain Controllers and systems that do not print. “Due to the possibility for exposure, domain controllers and Active Directory admin systems need to have the Print spooler service disabled. The recommended way to do this is using a Group Policy Object.”
Admin can also prevent remote print requests by using the Group Policy Object. Local printing will still be available for directly connected devices. <br />
Example: <br />
Stop-Service Spooler
REG ADD  "HKLM\SYSTEM\CurrentControlSet\Services\Spooler"  /v "Start" /t REG_DWORD /d "4" /f <br />

or using the following Powershell commands: <br />
Stop-Service -Name Spooler -Force

Set-Service -Name Spooler -StartupType Disabled <br />

![image](https://user-images.githubusercontent.com/63630561/138560380-300e948e-9d90-41d0-bf5d-41852c37cdf6.png)

If you need to print temporarily or a permanent fix has been released, you can enable the feature again. Here's how: <br />
1) Open Start. <br />
2) Search for PowerShell, right-click the top result, and select the Run as administrator problem. <br />
3) Type the following command to prevent the service from starting back up again during restart and press Enter: Set-Service -Name Spooler -StartupType Automatic <br />
4) Type the following command to stop the Print Spooler service and press Enter: <br />
5) Start-Service -Name Spooler <br />
![image](https://user-images.githubusercontent.com/63630561/138560361-e58c5b29-17c8-4117-9f6c-20cd62dfe44d.png)

If your computer is a non-domain or is part of a domain, then mitigation can also be accomplished using Group Policy.
To disable using Group Policy: <br />
1) Open Start <br />
2) Search for gpedit.msc and click OK to open the Local Group Policy Editor. <br />
3) Browse the following path: Computer Configuration > Administrative Templates > Printers <br />
4) On the right side, double-click the Allow Print Spooler to accept client connections: policy. <br />

![image](https://user-images.githubusercontent.com/63630561/138560994-5be06989-e291-4562-acdc-b915ff1dae76.png)

5) Select the Disabled option. <br />

![image](https://user-images.githubusercontent.com/63630561/138561017-d5668e11-b436-44c8-8cc9-a51757aa11f9.png)

6) Click the Apply button <br />
7) Click the OK button. <br />
**Disabling external network connections will prevent vulnerability.** <br />
If your Windows 10 machine is set up to share a printer (print server) then users will not be able to print with this setting.

**Make sure to restart the print spooler after it has been disabled.**

Microsoft released security updates July 6, 2021 (and included in subsequent updates as well) which includes a partial fix to this vulnerability. The update makes it where non-administrators will not be able to install drivers (signed or unsigned). The problem is that many home users and many organizations make a normal user an administrator to reduce frustrations and/or helpdesk calls. If a normal user is setup on the computer with administrator rights than this security update will not help. <br />

Another option to mitigate this vulnerability is to change the Group Policy settings for Point and Print Restrictions: <br />

1)  Open the group policy editor tool and go to Computer Configuration > Administrative Templates > Printers. <br />
2)  Configure the Point and Print Restrictions Group Policy setting as follows: <br />
    a)  Set the the Point and Print Restrictions Group Policy setting to "Enabled". <br />
    b)  "When installing drivers for a new connection": "Show warning and elevation prompt". <br />
    c)  "When updating drivers for an existing connection": "Show warning and elevation prompt". <br />
    
![image](https://user-images.githubusercontent.com/63630561/138598236-cf78f7a3-616e-495f-91d5-7fcd848abf1a.png)

*** It is highly recommended that this be applied to all machines that host the print spooler service <br />



To isolate the machine, most people think of simply unplugging the machine from the power source; however, some corporations may not want to leap right into this as having this particular machine offline may be very expensive so they may prefer to find alternative ways.



# Reproduction of the exploit <br />
The attacker has a few options depending on their attack environment. As of now, the exploits we are showing are patched and it needs to be verified that the CVE-2021-1675 patch has not been applied or roll back patches on the Windows target by downgrading to a previous build but all Window machines are vulnerable as of 4 July 2021.
PoC of PrintNightmare implementing a using Windows to attack appears to have a couple more things to adjust such as allowing anonymous logon. <br /> ![image](https://user-images.githubusercontent.com/83483181/138563101-9f947155-1b30-48fe-9794-cc27ce814ee5.png)

-linux based attacker has to use a  custom built "Impacket" version from github  to build an enviroment that can replicate the attack. <br />
For Linux: gitclone https://github.com/cube0x0/impacket https://github.com/cube0x0/CVE-2021-1675/blob/main/CVE-2021-1675.py was the python script that was built to share a path from the dirty DLL (Dynamic Link Library) to the targeted host from the outside device using Samba. <br />

PoC of PrintNightmare implementing a using Windows to attack appears to have a couple more things to adjust such as allowing anonymous logon.
 -share directory creation and staging for sharing using SMB and allowing for everyone to be granted anonymous logon.
 ![image](https://user-images.githubusercontent.com/83483181/138562699-6a58de15-100a-416b-9723-d8c88c94c757.png)


mkdir C:\share
icacls C:\share\ /T /grant Anonymous` logon:r
icacls C:\share\ /T /grant Everyone:r
New-SmbShare -Path C:\share -Name share -ReadAccess 'ANONYMOUS LOGON','Everyone'
REG ADD "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters" /v NullSessionPipes /t REG_MULTI_SZ /d srvsvc /f #This will overwrite existing NullSessionPipes
REG ADD "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters" /v NullSessionShares /t REG_MULTI_SZ /d share /f
REG ADD "HKLM\System\CurrentControlSet\Control\Lsa" /v EveryoneIncludesAnonymous /t REG_DWORD /d 1 /f
REG ADD "HKLM\System\CurrentControlSet\Control\Lsa" /v RestrictAnonymous /t REG_DWORD /d 0 /f
![image](https://user-images.githubusercontent.com/83483181/138563339-126b3403-4d19-40d0-a620-d2c75cf0c1e7.png)
msfvenom was used in the PoC that we studied to inject the DLL, which hosted a payload of a reverse shell on tcp giving RCE.
![image](https://user-images.githubusercontent.com/83483181/138563150-19ccde57-3363-45c4-94b2-3bf0305eb5dd.png)

You can attack with Windows or Linux machines but each has a different package and similar routes of using the Windows Print Spooler service of the target. The exploits used SYSTEM ACCOUNT to bypass local admin groups for LPE (Local Privilege Escalation) and msfvenom to build a payload with a reverse shell for the RCE (Remote code execution). <br />
# Related Links
https://blog.talosintelligence.com/2021/07/printnightmare-coverage.html <br />
https://www.cvedetails.com/cve-details.php?t=1&cve_id=CVE-2021-1675  <br />
https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-1675 <br />
https://github.com/cube0x0/CVE-2021-1675 <br />
https://www.splunk.com/en_us/blog/security/i-pity-the-spool-detecting-printnightmare-cve-2021-34527.html <br />
https://www.kb.cert.org/vuls/id/383432 <br />
https://docs.microsoft.com/en-us/windows-hardware/drivers/print/printer-driver-isolation <br />
https://us-cert.cisa.gov/sites/default/files/recommended_practices/MitigationsForVulnerabilitiesCSNetsISA_S508C.pdf <br />
https://www.securityweek.com/isolation-based-security-provides-prevention-and-enhances-incident-response <br />
https://www.windowscentral.com/how-mitigate-print-spooler-printnightmare-vulnerability-windows-10 <br />
https://support.microsoft.com/en-us/topic/kb5005010-restricting-installation-of-new-printer-drivers-after-applying-the-july-6-2021-updates-31b91c02-05bc-4ada-a7ea-183b129578a7 <br />
Resources <br />
https://user-images.githubusercontent.com/83483181/138562699-6a58de15-100a-416b-9723-d8c88c94c757.png <br />
https://github.com/nemo-wq/PrintNightmare-CVE-2021-34527 <br />
https://github.com/cube0x0/CVE-2021-1675 <br />



https://user-images.githubusercontent.com/83483181/138562699-6a58de15-100a-416b-9723-d8c88c94c757.png
https://user-images.githubusercontent.com/83483181/138563101-9f947155-1b30-48fe-9794-cc27ce814ee5.png
https://user-images.githubusercontent.com/63630561/138561017-d5668e11-b436-44c8-8cc9-a51757aa11f9.png
https://user-images.githubusercontent.com/63630561/138560994-5be06989-e291-4562-acdc-b915ff1dae76.png
https://user-images.githubusercontent.com/63630561/138560994-5be06989-e291-4562-acdc-b915ff1dae76.png
