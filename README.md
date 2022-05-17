# KodeKloud Linux Basics: Security and File Permission

[KodeKloud Linux Basics Course Notes Table of Contents](https://github.com/pslucas0212/LinuxBasics)

## Security and File Permissions
Security in Linux is a vast topic covers many topics
- Acess Controls - Controls who can acces the system and which resources can be accessed
- PAM - Pluggable Authentication Modle - Used to authenticate users to programs and services in Linux
- Network security - Used to restrict or allow access to services listening on the server.  Secuirty can be applied to services using networking with iptables and firewalld
- SELinux - security policies to isolate applications from each other while running on the system. 
- SSH hardening - Secure access to a server across an unsecured netowkr
  
#### Linux Accounts
- Access Control
- Every user on linux has a linux account with user name, user id or UID which is unique to each user, and password to logon to the system.    Information about users is stored in the /etc/passwd file
- A Linus group is a collection of users that have a common need for accessing particular Linux resources.  Information about groups is stored in the /etc/group file.  Each group have a unique id called the gid
  
- Each user has a username, unique id - UID and belongs to a group with a group id - GID.  A user can be part of mutliple groups.  The system will create a group for the user with same GID as the UID.   All stores information about the home directory and shell.  Run the following information to get user information:
```
$ id pslucas
uid=1000(pslucas) gid=1000(pslucas) groups=1000(pslucas),10(wheel)
```
- This shows the UID, GID and groups that the user is part of.
```
grep -i pslucas /etc/passwd
pslucas:x:1000:1000:Paul Lucas:/home/pslucas:/bin/bash
  ```
- we can see see the users home directory and shell by grepping on their name in the /etc/passwd file
  
  
User account type refers to individual users that need access to the Linux syesetm

- Superuser account whcih is roothas a uid = 0 and has unrestricted and control over the linux system including other users
- System accounts are usually created by the Linux installation for software and services that do not run as root - UID <100 or between 500 - 1000.  They usually don't have a dedciated home directoy.  If they have a home directory it is not usually under /home
- Service accounts are similar to service account - run nginx, etc. 
                            
- Run who command to see who is logged in and the last time the system was rebooted
```
$ who
pslucas  pts/0        2022-05-10 15:39 (10.1.1.4)
```
- the last command shows the recorde of all last logged in users and whent the system was rebooted
```
$ last
pslucas  pts/0        10.1.1.4         Tue May 10 15:39   still logged in
pslucas  pts/0        10.1.1.4         Thu May  5 13:33 - 22:01  (08:28)
pslucas  pts/0        10.1.1.4         Wed May  4 08:10 - 17:46  (09:36)
...
```
#### Switch users
You can use the su command to switch to root or another user, but this is not recommended as you need the password of the user you are switching to.  You can run a specific a command with -c
```
$ su -
$ su -c whoami
```
Sudo is the recommended command for priveleged escalation.  To run commands as root user.  The user is prompted for their password.  Sudo users and privelages are defined in the /etc/sudoers file.    Only users listed in the sudoers file can do root lever permission.  With sudo we don't need to ever loing as the root user.

In the sudoer file you can give limited root capabilites to users, like the ability to only reboot the system.  With sudo enabled file you can eliminate the need to ever login as the root user by setting a nologin in the /etc/passwd file

### Sudoer file
Uses a hash or pound sign for comments 
The  field is user or group to which priveleages granted starts with %
Second field is the host where user can be granted sudo capabilites.  usually ALL
The third field (ALL) imples user and groups that can run commands
The foruth field is the command that can be run ALL means the user can run any command
  
#### User Management
Managing Users:
usesadd Command to Add (create user) user; see user bob's uid and gid, home directory and shell; "see" bob's password setting in the /etc/shadow file, set Bob's password, check how you are logged into the system and change your password...
- Create user bob and look the userid, group id, home directoy and shell setup for bob
```
$ sudo useradd bob
[sudo] password for pslucas: 
$ 
$ grep -i bob /etc/passwd
bob:x:1082:1082::/home/bob:/bin/bash
```
- set or change bob's password use passw command follwed by the users name
```
$ sudo grep -i bob /etc/shadow
[sudo] password for pslucas: 
bob:!!:19122:0:99999:7:::
$ sudo passwd bob
Changing password for user bob.
New password: 
Retype new password: 
passwd: all authentication tokens updated successfully.
$ sudo grep -i bob /etc/shadow
bob:$6$tYGnBXovmwzuc.7i$WEXyoLu8jMfBKbWWzk6Z5oy.0hndF/Rw5FeBveGcIKoSA9P8rkIqu31xLP1m6GHYs3pr9QxytCX74a0Z9mfVB/:19122:0:99999:7:::
```
Now login as bob
```
$ whoami
bob
```
Bob can now change his password if he wants


  
Common options to use with useradd
Switch | Switch argument
-------|----------------
-c | custom comments
-d | customer home directory
-e | expirdy date
-g | specific GID
-G | creat user with mutilple secondary groups
-s |specifiy login shell
-u | specify UID

```
$ sudo useradd -u 1959 -g 10 -d /home/samuel -s /bin/sh -c "Mercury Project Member" sam
$ id sam
uid=1959(sam) gid=10(wheel) groups=10(wheel)
grep -i sam /etc/passwd
sam:x:1959:10:Mercury Project Member:/home/samuel:/bin/sh
```
Delete user  
```
$ sudo userdel bob
```
Create group
```
$ sudo groupadd -g 1011 developer
```
Add a user to group - use the usermod command with -a for append to supplement groups -G to specifiy the group followed by the group name and user name
```
$ sudo usermod -a -G developer sam
```
Groups command shows groups the logged in used is a member of..  User sam as an example
```
$ groups
wheel developer sam
```
Delete group
```
$ groupdel developer
```

#### Access Control Files
Access Controls files are found under /etc directory, are only accessible to root, and should never be modified directly with vi or VIM, but with their "special" editor.    Usually can be read by any user, but must be root modify

- /etc/passwd - contains information about users including user name, id, groups, home directory and shell
```
$ grep -i sam /etc/passwd
sam:x:1959:10:Mercury Project Member:/home/samuel:/bin/sh
```
- USERNAME:PASSWORD:UID:GID:GECOS:HOMEDIR:SHELL  
- Password is always x as the password is kept in the /etc/shadow file.  The GECOS CSV comma separated of user information that can optionally include full name, phone number and location information is optional 


- /etc/shadow - contains users password that is hashed
```
sudo grep -i sam /etc/shadow
sam:$6$l3YrBEiCQdIf1u0a$ER7lXCTDyfrXUid2gNfX7UTcS9BPa/tgdwkoSglrFNtZq5IQK8EnYNrOktoexIXLkgxvF6A7GIUMpz224EUVw.:19122:0:99999:7:::
```
- USERNAME:PASSWORD:LASTCHANGE:MINAGE:MAXAGE:WARN:INACTIVE:EXPDATE
username, hashed password, the rest self explanatory - Note: LASTCHANGE the date since the password last changed is Epic which is the number of days since January 1st 1970.  Minimum and max days before they need to change password,  number of days to warn the user before the password expiration.  EXPDAT - nunmber of days when the account expires in an epic date format 


- /etc/groups - contains groups
```
$ grep -i sam /etc/group
sam:x:1082:sam
```
NAME:PASSWORD:GID:MEMBERS
Group name, password set to x saved in the shadow file, Group ID, memeber list comma separated
 
 
 
 
### Linux File Permissions  
  
Use ls -l command can be used to determine the type of file and its permissions.  The first letter in the column determines the file type

```
$ ls -l
total 1120
-rw-r--r--  1 root   root    2981 Oct 30  2021 adduser.conf
drwxr-xr-x  3 root   root    4096 Oct 30  2021 alsa
drwxr-xr-x  2 root   root    4096 May 11 14:32 alternatives
drwxr-xr-x  4 root   root    4096 May 11 14:31 apache2
drwxr-xr-x  4 root   root    4096 May 11 15:12 apparmor.d
drwxr-xr-x  8 root   root    4096 Oct 30  2021 apt
drwxr-xr-x  3 root   root    4096 Oct 30  2021 avahi
-rw-r--r--  1 root   root    1994 Jan  3  2021 bash.bashrc
-rw-r--r--  1 root   root      45 Jan 24  2020 bash_completion
drwxr-xr-x  2 root   root    4096 May 11 14:32 bash_completion.d
-rw-r--r--  1 root   root     367 Oct  9  2021 bindresvport.blacklist
```
  
File Type | Identifier
--------- | ----------
Directory | d
Regular File | -
Character Devicd | c
Block device | b  
Link | l
Socket File | s
Named Pipe | p

 
File permission follow the first coloumn   -rwxrwxr-x
The characters can be used to determine the ownser, group and other permissions

owner | group | other
------|-------|------
rwx | rwx | rwx
u | g | o

first three characters is for User - u  
seconde three charactars is for Group - g  
Third three characters is for Other - o  
  
File Permissions bit setings
  
Bit | Purpose | Octal Value
--- | ------- | ------------
 r | Read | 4
 w | Write | 2
 x | Execute | 1  
 '- '| No permission | 0
  
Directory Permissions that we see for a file are still applicable
r - read directory
w - write directory
x - execute - 
  
Bit | Purpose | Octal Value
--- | ------- | ------------
 r | Read | 4
 w | Write | 2
 x | Execute | 1
'-' | No Permission | 0  
  
Directory permission heirachy  
Permissions first check owner if owner then only owner permissions applied and the rest of the permissions are ignored
Next check group permission if not owner, but member of group then group permissions apply  and the rest of the permissions are ignored
Finally check other permission
  
File Permission Example  
  
Example 1 | Example 2 | Example 3 | Example 4 
--------- | --------- | --------- | ---------
rwx | rw- | -wx | r-x
4+2+1 | 4+2+0 | 0+2+1 | 4+0+1
7 | 6 | 3 | 5  
  
Changing file and directory permissions  
Used chmod or change mode command to change file permissions
chmod <permissions> file  
Change numerically or symbollically  
With the symbolic mode you specify - u: user, g: group or o:other and grant access with a + or remove access with a -  

Symbolic mode example
 ```
 $ chmod u+rwx test-file
 $ chmod ugo+r test-file
 $ chmod o-rwx test-file
 $ chmod u+rwx,g+r-x,o-rwx test-file
```

First digit is for user or owner, second digit for group and and third digit for other
Numeric mode example
```
$ chmod 777 test-file
$ chmod 555 test-file
$ chmod 660 test-file
$ chmod 750 test-file
```
  

Change ownership and group  - chown owner:group file
Change ownership to bob and group
```
$ chown bob:developer test-file
```
Change just the owner
```
$ chown bob andoid.pak
```
Change only the group
```
$ chgrp androd. test-file
```  

If you want to change permissions or ownership of directory and all its contents use the -R recursive swith
```
$ sudo chown -R mercury sports
```
This example changes the owner for the sports directory and its contents to mercury
  
### SSH and SCP  
 
SSH used for logging into and executing commands on a remote computer  
ssh <hostname or ip adderss>  
ssh <user@hostname or IP address>  
ssh -l <user> <hostname or IP address>
The remote serve needs to have an SSH service running and port 22 available.
To access remote machine you need a valid user id and password or ssh key                                                                                  
```
$ ssh devapp01
```
This uses the id that you are logged on locally to acess the remote server  
 
You can enable the passwordlesss login with keys - public and private key  
Setting up password-less SSH example:  
1. Create key-pair
```
$ ssh-keygen -t rsa
```
You can except the defaults or provide custoem information  
 
Notice where the keys are stored:  
Public key - /home/bob/.ssh/id_rsa.pub  
Private key - /home/bob/.ssh/id_rsa

2. Copy remote key to target remote server  
```  
$ ssh-copy-id bob@devapp01
```
The public key is now stored on the remote server here:  
/home/bob/.ssh/authorized_keys  
  
#### SCP  
SCP - secure copy for use with remote servers using TSL/SSL
```
$ scp /home/bob/caleston-code.tar.gz devapp01:/home/bob
```
copy directories and files use the -r switch
Copy directory and preserve permissions (use -p) example
```
$ scp -pr /home/bob/media /devapp01:/home/bob
```

### Network Security
To connect to a remote server you need user and password authentication or SSH password protection.  Port 22 needs to be open to recieve SSH requests.
  
We need to control network security.  We can apply network security with appliances to control network traffic flowing through the network.  We can also use IPTable rules and firewallD to control network security with Linux
 
As an example... Suppose you have a client machine with x.x.x.187, an application server with x.x.x.10 and a database server with x.x.x.11. Nothing is current blocked.  
  
 Say we want the client machine to connect to app server, we need ssh/port 20 and HTTP/port 80 on the app server.  The app server needs to speak to the DB server on port 5432 and software repo server x.x.x.15 on HTTP/port 80.  But we want to block outgoing internet request from the app server.  Finally we only want db server to speak to the app server
  
We will use IPTables to filter traffic.  IPTables are installed on RHEL and CentOS as part of the OS.  On ubuntu we would need to install IPTables
```
$ sudo apt install iptables
```
List default rule run:
```
$ sudo iptables -L
```

We will see three types of rules or chains
- INPUT - input chaing is applicable to network traffic coming into the system.  For example the appserver would need a rule to allow SSH/port 22 traffic to enter the server
- FORWARD - used in network routers to forward data to other devices.  Not commonly used Linux servers
- OUTPUT - responsible for connections intiated by the server to another server

Default rules allow all input and out put
  
Called a chain of rules as they follow the order they are "created" and each rule is executed in order.  The flow through the chain either accepts the packet and it goes on to the next rule or is dropped.
  
We can also consider both the source of the request as well as the destination of the request

  
An example input rule - accept tcp from the app server to the application server on port 22
 ```
$ iptables -A INPUT -p tcp -s 172.16.238.187 --dport 22 -j ACCEPT
```
  
IPTable Options
Option | Description
-------|------------
 -A | Add Rule
 -p | protocol
 -s | source
 -d | Destination
 --dport | Destination Port
 -j | Action to take
  
 -s source coula also be a ip address range.
  
If another client tried to connect to the app server it would flow through as the rule accepts all input connections.
  
We only want the server to use SSH/22 port
  
```
$ iptable -A INPUT -p tcp --dport 22 -j DROP
```
Now only client a can SSH to the app server.  The request flow follows the list (chain) of rules.  The sequence of rules are important.  The rules are implemented top to bottom

use -I to insert a rule at the top of the chain

To delete rule use -D and the postion of the rule
```
$ iptables -D OUTPUT 5
```
We secure the Database server with 3 rules.  1 rule on app server and2 rules are running on the db server
```
$ iptables -A OUTPUT -p tcp -d 172.16.238.11 --dport 5432 -j ACCEPT
```
DB server rules
```
$ iptables -A INPUT -p tcp -s 172.16.238.10 --dport 5432 -j ACCEPT
$ iptables -A INPUT -p tcp --dport 5432 -j DROP
```

Do we need a rule to accept responses from the database server to the app server.  No we don't. The response is accept on any random port on the app server. 
  
  
Example allow SSH/22 and HTTP/80 from client (172.16.238.187) but drop all other tcp/udp traffic
```
$ sudo iptables -A INPUT -p tcp -s 172.16.238.187 --dport 22 -j ACCEPT
$ sudo iptables -A INPUT -p tcp -s 172.16.238.187 --dport 80 -j ACCEPT
$ sudo iptables -A INPUT -j DROP
```
Check IPTables rules
```
sudo iptables -L
Chain INPUT (policy ACCEPT)
target     prot opt source               destination         
ACCEPT     tcp  --  caleston-lp10        anywhere             tcp dpt:ssh
ACCEPT     tcp  --  caleston-lp10        anywhere             tcp dpt:http
DROP       all  --  anywhere             anywhere            

Chain FORWARD (policy ACCEPT)
target     prot opt source               destination         

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination 
```

