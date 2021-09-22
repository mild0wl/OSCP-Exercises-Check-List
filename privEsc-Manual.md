| Linux | Windows |
| whoami | whoami |
| id | net user student |
| cat /etc/passwd | net user |
| hostname | hostname |
| cat /etc/issue OR cat /etc/*-release OR uname -a OR cat /proc/version | systeminfo | findstr /B /C:"OS NAME" /C:"OS Version" /C:"System Type" |
| ps aux | tasklist /SVC |
| ifconfig OR ip a | ipconfig /all |
| /sbin/route | route print |
| netstat -ano OR ss -anop | netstat -anotu |
| cat /etc/iptables [check file permissions] | netsh advfirewall show currentprofile |
| iptables-save and iptables-restore | netsh advfirewall show rule name=all |
| cat /etc/crontab or crontab -l | schtasks /query /fo LIST /v |
| dpkg -l | wmic product get name, version, vendor |
| [x] | wmic qfe get Caption, Description, HotFixID, InstalledOn |
| find / -writable -type d 2>>/dev/null | accesschk.exe -uws “Everyone” “C:\” |
| find / -writable -type f -not -path “/proc/*” 2>>/dev/null | Get-ChildItem “\” -Recurse | Get-ACL | ?{$_.AccessToString -match "Everyone\sAllow\s\sModify"} |
| cat /etc/fstab AND mount AND /bin/lsblk | mountvol |
| lsmod | driverquery.exe /v /fo csv | ConvertFrom-CSV | Select-Object
‘Display Name’, ‘Start Mode’, Path |
| /sbin/modinfo libata | Get-WmiObject Win32_PnPSignedDriver | Select-Object DeviceName,
DriverVersion, Manufacturer | Where-Object {$_.DeviceName -like "*VMware*"} |
| find / -perm -u=s -type f 2>/dev/null | reg query HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer |
|  | reg query HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer |
| ls -la /etc/passwd  |  |
| ls -la /etc/shadow |  |
| sudo -l | cmdkey /list |
| cat .bash_history |  |
| cat ~/.bashrc |  |
|  |  |
