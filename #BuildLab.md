Follow this excellent guide -https://robertscocca.medium.com/building-an-active-directory-lab-82170dd73fb4

- Create users, groups, and OUs
- Make sure you have at least one user in the Domain Admins group
- Make sure you add a local administrators group and GPO so some admin users other than Domain Admin inherit localadmin onto machines within certain OUs you set [guide](https://thesysadminchannel.com/add-local-administrators-via-gpo-group-policy/)
- Set a GPO to disable Windows Defender as shown in the guide
- Make sure you add an SPN as shown in the guide
- Make sure your (web)server has an active SPN
- Set delegation for your webserver to test Un/Constrained delegation (just set to CIFS of your Domain Controller)
  - When setting constrained delegation ensure to set 'any protocol' for delegation - NOT 'just kerberos'

Installing Active Directory Certificate Services on the DC - https://www.virtuallyboring.com/setup-microsoft-active-directory-certificate-services-ad-cs/
