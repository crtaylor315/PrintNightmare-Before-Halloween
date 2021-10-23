# Welcome to our PrintNightmare exploit Capstone writeup.
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

 Detecting and or Recognizing What an Attack Looks Like on a Victim’s OS with the PrintNightMare Exploit
Now for the savvy computer advanced user, it’s a no brainer to disable any Windows Print Spooler service but if this is like a foreign language and by the way it is, then the admin of the computer or cyber security blue team can take 6 easy steps to disable the Print Spooler option in your operating system.
1.)	In Start Menu run Powershell as an administrator 
2.)	Type and Enter Stop-service -Name Spooler -Force in command line
3.)	To Block and Prevent Service from restarting when system gets rebooted enter the following command Set-Service -Name Spooler -StartupType Disabled
4.)	Open Start and search for gpedit.msc. 
5.)	Now open computer configuration < Administrative Templates < Printers. When you see Allow Print Spooler to Accept client connections double click
6.)	The final Step is to select Disabled option and click it. 
		
The Print Spooler is the middleman between your computer and your printer. This is its basic function to manage print jobs. Thus, its highly recommended by security professionals to disable this option.
There are tools like Semperis’ Directory Services Protector (DPS) that continuously detects and scans systems for red flags or indicators of compromise on an operating system. 
Some researchers have observed and logged activity for what a compromised system using the PrintNightMare might look like. The use of malicious DLL files are noted, and remote use of SMB share is redirected by attacker to inject into the memory process of the targeted system, and finalizes attack by loading the DLL in the Print Service Spooler. Other red flags to look for, using Process Explorer, include processes being spawned, error codes of 808 from event source are visible to victim, in event a new printer is added or updated to system 316 code generates and well basically the OS will be getting lots of error messages and codes.
Other eye openers to keep an eye open for would be creation of new DLL files under spool drivers, suspicious activity of spawning processes from Print Service Spooler, any outbound connection originating from child processes relating to Print Spooler services, and Malware detection from Print Spooler path. Once your machine has been compromised the attackers now remotely and gradually take over your entire system. This is why is its critical to disable the Print Spooler option if your using a supported version of Windows to avoid being hacked.  

Damage Control & the Recovery Process Once a System has been Compromised  
Once a system has been compromised its important to isolate the damage in a safe environment and is always a good idea to have backup operating system in case it crashes or was targeted. In the case, where the entire system is taken over the best solution is to delete and or erase everything on your hard drive and back it up with your backup copy that was taken prior to attack. If no backup copy is readily available, then unfortunately there is a lesson to be learned—and sometimes these lessons are hard but well learned. A system restore will be needed from an earlier uncompromised time.
After a reinstallation of Microsoft Windows 10 or newest version has been installed make sure all security patches are up to date and immediately disable the Print Spooler option. Keeping your Windows operating system updated and patched in a key factor in cyber security and is highly recommended by all cyber security professionals in the industry. Often some of us get lazy or simply forget to update our computers but there is an option which can be enabled for automatic updates on system and software which can help keep your machine running and operating with less worry of an attack; please note, however, attackers will always find ways or backdoors to attack a victim (s). By reinstalling Windows, most software including printer drivers will be updated and or patched. A rule of thumb, avoid downloading any suspicious or weird links which can be malicious malware, viruses, or bad stuff your os does not need. Moreover, the manufacture’s website has latest drivers and patches available for public use. The deletion of unnecessary registry keys helps to avoid this specific type of attack. Always scan your computer and use tools to help detect and or protect. Frequently, run chkdsk utility to check for disk errors relating to the Print Spooler service. Make sure to change Spooler recovery options to avoid an automatic restart of software. Also, resetting internet settings can help system run smoother without interference from Spooler. If possible, replace the infection printer. These are some steps that can be taken when recovering from PrintNightmare exploit using the print spooler vulnerability.





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
First, make sure that all security patches have been installed then perform the following workaround for an added layer of security. <br />
CISA (Cybersecurity and Infrastructure Security Agency) recommends administrators to disable the print spooler service in Domain Controllers and systems that do not print. _“Due to the possibility for exposure, domain controllers and Active Directory admin systems need to have the Print spooler service disabled. The recommended way to do this is using a Group Policy Object.”_ <br />
Admin can also prevent remote print requests by using the Group Policy Object. Local printing will still be available for directly connected devices.

Example: <br />
Stop-Service Spooler
REG ADD  "HKLM\SYSTEM\CurrentControlSet\Services\Spooler"  /v "Start" /t REG_DWORD /d "4" /f <br />

or using the following Powershell commands: <br />
Stop-Service -Name Spooler -Force

Set-Service -Name Spooler -StartupType Disabled <br />

![image](https://user-images.githubusercontent.com/63630561/138560380-300e948e-9d90-41d0-bf5d-41852c37cdf6.png)

If you need to print temporarily or a permanent fix has been released, you can enable the feature again. Here's how:

1)	Open Start.
2)	Search for PowerShell, right-click the top result and select the Run as administrator problem.
3)	Type the following command to prevent the service from starting back up again during restart and press Enter:
		Set-Service -Name Spooler -StartupType Automatic
4)	Type the following command to stop the Print Spooler service and press Enter: <br/>
		Start-Service -Name Spooler

![image](https://user-images.githubusercontent.com/63630561/138560361-e58c5b29-17c8-4117-9f6c-20cd62dfe44d.png)

If your computer is a non-domain or is part of a Domain then mitigation can also be accomplished using Group Policy.

To disable using Group Policy:
1)	Open Start
2)	Search for gpedit.msc and click OK to open the Local Group Policy Editor.
3)	Browse the following path:
		Computer Configuration > Administrative Templates > Printers
4)	On the right side, double-click the Allow Print Spooler to accept client connections: policy.

![image](https://user-images.githubusercontent.com/63630561/138560994-5be06989-e291-4562-acdc-b915ff1dae76.png)

5)	Select the Disabled option.

![image](https://user-images.githubusercontent.com/63630561/138561017-d5668e11-b436-44c8-8cc9-a51757aa11f9.png)

6)	Click the Apply button
7)	Click the OK button.

*** Disabling external network connections will prevent the vulnerability. If your Windows 10 machine is setup to share out a printer (print server) then users will not be able to print with this setting.

**Make sure to restart the print spooler after it has been disabled**

To isolate the machine, most people think of simply unplugging the machine from the power source; however, some corporations may not want to leap right into this as having this particular machine offline may be very expensive so they may prefer to find alternative ways. 

# Reproduction of the exploit <br />
Reproduction
Attacker has a few options depending on thier attack enviroment. As of now the exploits we are showing are patched and needs to verified that cve-2021-1675 patch has not been applied or roll back patches on the Windows target by downgrading to a previous build but all Window machines are vulnerable as of 4th july 2021  
A PoC of PrintNightmare implementing a Python script
-linux based attacker has to use a  custom built "Impacket" version from github  to build an enviroment that can replicate the attack. for linux.) git clone https://github.com/cube0x0/impacket
https://github.com/cube0x0/CVE-2021-1675/blob/main/CVE-2021-1675.py was the python script that was built to share a a path to the dirty DLL(Dynamic Link Library) to the targeted host from the outside device using samba
B PoC of PrintNightmare implementing a Using windows to attack appears to have a couple more things to adjust such as allowing anonymous logon 
-share directory creation and staging for sharing using SMB and allowing for everyone to be granted anonymous logon
![image](https://user-images.githubusercontent.com/83483181/138562699-6a58de15-100a-416b-9723-d8c88c94c757.png)

mkdir C:\share
icacls C:\share\ /T /grant Anonymous` logon:r
icacls C:\share\ /T /grant Everyone:r
New-SmbShare -Path C:\share -Name share -ReadAccess 'ANONYMOUS LOGON','Everyone'
REG ADD "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters" /v NullSessionPipes /t REG_MULTI_SZ /d srvsvc /f #This will overwrite existing NullSessionPipes
REG ADD "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters" /v NullSessionShares /t REG_MULTI_SZ /d share /f
REG ADD "HKLM\System\CurrentControlSet\Control\Lsa" /v EveryoneIncludesAnonymous /t REG_DWORD /d 1 /f
REG ADD "HKLM\System\CurrentControlSet\Control\Lsa" /v RestrictAnonymous /t REG_DWORD /d 0 /f

msfvenom, was used in the PoC  that we studied to inject the DynamicLinkLibrary which hosted a payload of a reverse shell on tcp giving remote code execution.

- You can attack with Windows or Linux machines but each has a different package but similar routes of using the (Windows)print spooler service of the target
 The exploits  used  SYSTEM ACCOUNT( "computer itself" account) to bypass local admin groups for LPE(local Previlege Escalation) and msfvenom to build a payload with a reverse shell for the RCE(Remote code execution)

# Related Links
https://blog.talosintelligence.com/2021/07/printnightmare-coverage.html <br />
https://www.cvedetails.com/cve-details.php?t=1&cve_id=CVE-2021-1675  <br />
https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-1675 <br />
https://github.com/cube0x0/CVE-2021-1675 <br />
https://www.splunk.com/en_us/blog/security/i-pity-the-spool-detecting-printnightmare-cve-2021-34527.html <br />
https://www.kb.cert.org/vuls/id/383432 <br />
https://docs.microsoft.com/en-us/windows-hardware/drivers/print/printer-driver-isolation <br />
https://us-cert.cisa.gov/sites/default/files/recommended_practices/MitigationsForVulnerabilitiesCSNetsISA_S508C.pdf <br />
https://www.securityweek.com/isolation-based-security-provides-prevention-and-enhances-incident-response
https://www.windowscentral.com/how-mitigate-print-spooler-printnightmare-vulnerability-windows-10
