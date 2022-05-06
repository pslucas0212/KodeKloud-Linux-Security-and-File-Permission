# KodeKloud-Linux-Security-and-File-Permission


## Security and File Permissions

- Acess Controls -
- PAM - Pluggable Authentication Modle - authenticate users to programs and services
- Network security - secuirty applied to services usingnetworking with iptables and firewalld
- SELinux - security policies to isolate services/processes running on the system
- SSH hardening - security login
  
#### Linux Accounts
- Every user on linux has a linux accoutn with user name, user id, and password to logon to the system.  Ever user has a unique user id.  Information about users is stored in the /etc/passwd file
- Group is a collection of users that have a common need for accessing particular Linux resources.  Information about groups is stored in the /etc/group file.  Each group have a unique id called the gid
  
- Each user has a username, unique id - UID and belongs to a group with a group id - GID.  Run the following information to get user information:
```
$ id <username>
$ grep <username> /etc/passwd
  ```
- we can see see the users home director and shell by grepping on their name in the /etc/passwd file
  
User account type refers to individual users that need access to Linux serves

- Superuser account has a uid = 0 and has complet control over the linux system
- System accounts - UID <100 or between 500 - 1000
- Service account - run nginx, etc.
                            
- Run who command to see who is logged in and the last time the system was rebooted
```
$ who
```
#### Switch users
You can use the su command to switch to root or another user, but this is not recommended as you need the password of the user you are switching to
```
$ su -
$ su -c whoami
```
Sudo is the recommended command for priveleged escalation.  To run commands as root user.  The user is prompted for their password.  Sudo users and privelees are defined in the /etc/sudoers file.    
sudoers file
  
#### User Management
Managing Users:
Commands to Add (create user) user; see user bob's uid and gid, home directory and shell; "see" bob's password setting in the /etc/shadow file, set Bob's password, check how you are logged into the system and change your password...
```
$ useradd bob
$ grep -i bob /etc/passwd
$ grep -i bob /etc/shadow
$ passwd bob
$ whoami
```
  
Common options to use with useradd
* -c custom comments
* -d customer home directory
* -e expirdy date
* -G creat use with mutilple secondary groups
* -s specifiy login shell
* -u specify UID

```
$ useradd -u 1099 -g 1009 -d /home/robert -s /bin/bash -c "Mercury Project Member" bob
$ id bob
$ grep -i bob /etc/passwd
```
Delete user  
```
  $ userdel bob
```
Create group
```
$ groupadd -g 1011 developer
```
Delete group
```
$ groupdel developer
```
#### Access Control Files
These files are found under /etc directory, are only accessible to root, and should never be modified directly with vi or VIM, but with their "special" editor.  

- /etc/passwd - contains information about users including user name, id, groups, home directory and shell
```
$ grep -i bob /etc/passwd
```
- /etc/shadow - containers users password that is hashed
- /etc/groups - contains groups
  
/etc/passwd contains user information  
```
$ grep -i pslucas /etc/passwd
```
USERNAME:PASSWORD:UID:GID:GECOS:HOMEDIR:SHELL  
pslucas:x:1000:1000::/home/pslucas:/bin/bash  
Password is always x as the password is kept in the /etc/shadow file.  The GECOS CSV comma separated other information include full name, phone number and location information is optional  
  
/etc/shadow
```
$ grep -i pslucas /etc/passwd 
```
USERNAME:PASSWORD:LASTCHANGE:MINAGE:MAXAGE:WARN:INACTIVE:EXPDATE
username, hashed password, the rest self explanatory - Note: LASTCHANGE the date since the password last changed is Epic.  Minimum and max days before they need to change password,  number of days to warn the user before the password expiration.  EXPDAT - nunmber of days when the account expires in an epic date format   
  
/etc/group
```
$ grep -i pslucas /etc/group
```
NAME:PASSWORD:GID:MEMBERS
Group name, password set to x saved in the shadow file, Group ID, memeber list comma separated
 
#### Linux File Permissions  
  
Use ls -l command to get information about file type and permissions  
  
File Type | Identifier
--------- | ----------
Directory | d
Regular File | -
Character Devicd | c
Link | l
Socket File | s
Pipe | p
Block device | b  
 
File permission example  -rwxrwxr-x
first three characters is for User - u  
seconde three charactars is for Group - g  
Third three characters is for Other - o  
  
File Permissions  
  
Bit | Purpose | Octal Value
--- | ------- | ------------
 r | Read | 4
 w | Write | 2
 x | Execute | 1  
  
Directory Permissions  
  
Bit | Purpose | Octal Value
--- | ------- | ------------
 r | Read | 4
 w | Write | 2
 x | Execute | 1
'-' | No Permission | 0  
  
Directory permission heirachy  
Permissions first check owner if owner then only owner permissions applied  
Next check group permission if not owner, but member of group then group permissions apply  
Finally check other permission
  
File Permission Example  
  
Example 1 | Example 2 | Example 3 | Example 4
--------- | --------- | --------- | ---------
rwx | rw- | -wx | r-x
4+2+1 | 4+2+0 | 0+2+1 | 4+0+1
7 | 6 | 3 | 5  
  
Changing file permissions  
chmod <permissions> file  
Change numerically or symbollically  
Symbolic mode example
 ```
 $ chmod u+rwx test-file
 $ chmod ugo+r test-file
 $ chmod o-rwx test-file
 $ chmod u+rwx,g+r-x,o-rwx test-file
```
Numeric mode example
 ```
 $ chmod 777 test-file
 $ chmod 555 test-file
 $ chmod 660 test-file
 $ chmod 750 test-file
```
  

Change ownership and group  - chown owner:group file
```
$ chown bob:developer test-file
$ chown bob andoid.pak
$ chgrp androd. test-file
```  
  
#### SSH and SCP  
SSH for logging into and executing commands on a remote computer  
ssh <hostname  or ip adderss>  
ssh <user@hostname>  
ssh -l <user> <hostname>
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
Copy directory and preserve permissions example
```
$ scp -pr /home/bob/media /devapp01:/home/bob
```
  
