Follow this excellent guide -https://robertscocca.medium.com/building-an-active-directory-lab-82170dd73fb4

Create users, groups, and OUs
Make sure you have at least one user in the Domain Admins group
Make sure you add a local administrators group and GPO so some admins get delegated localadmin on machines
Make sure you add an SPN as shown in the guide
Set a GPO to disable Windows Defender as shown in the guide
Make sure your (web)server has an active SPN
Set delegation for your webserver to test Un/Constrained delegation
