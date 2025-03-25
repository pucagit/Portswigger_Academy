# Business Logic
Business logic vulnerabilities are flaws in the design and implementation of an application that allow an attacker to elicit unintended behavior. This potentially enables attackers to manipulate legitimate functionality to achieve a malicious goal. These flaws are generally the result of failing to anticipate unusual application states that may occur and, consequently, failing to handle them safely.

### LAB: Excessive trust in client-side controls
Change the price in the body of the add to cart request (`POST /cart HTTP/2`):

    productId=1&redir=PRODUCT&quantity=1&price=10

We can now by this product with a much lower price than expected.

### LAB: High-level logic vulnerability
Change the quantity in the body of the add to cart request (`POST /cart HTTP/2`) of another product which cost $99.45:

    productId=17&redir=PRODUCT&quantity=-13

Now add the target product to cart which price is \$1337.00. The total cart price is now $ \$1337.00 - 13 \times \$99.45 = \$44.15$ which is a price we can buy.

### LAB: Low-level logic flaw
Send the add to cart request to Intruder and set the `quantity=99`. 
Insert a null payload and start a sniper attack that loops infinitely until the price go beyond its limit, loops from it min value and finally return to a value near 0. Here we can add some other products manually so that the total price now is a positive number and less than $100.

### LAB: Inconsistent handling of exceptional input
Notice that only accounts with an email address ending in `@dontwannacry.com` is accessible to the admin panel.
Notice that for a very long email (more than 255 characters), the email is then truncated to a 255 characters string.
To bypass this limitation, register with an email so that `...@dontwannacry.com` is exactly 255 characters long and the `exploit-0ab70043030b856983f7a54701f50040.exploit-server.net` after it would be truncated but still the email is sent to this email domain:

    aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@dontwannacry.com.exploit-0ab70043030b856983f7a54701f50040.exploit-server.net

The final email would be a valid admin email and so access to the admin panel is allowed.

### LAB: Inconsistent security controls
Register a new account using the given email address.
After successful registration, login to that account and change the email to `a@dontwannacry.com` which then makes it able to visit the admin panel and delete user `carlos`.

### LAB: Weak isolation on dual-use endpoint
Login using `wiener:peter` credential. Use the change password function and send that request to repeater.
Modify the body of the `POST /my-account/change-password HTTP/2`:

    csrf=JnkCjHKuDLp3Zuik44F4XpVoc7lJTv3X&username=administrator&new-password-1=123&new-password-2=123

The request is accepted by the server and the admin's password is changed. Login using `administrator:123` to access the admin panel and delete user `carlos`.

### LAB: Insufficient workflow validation
Same as Lab Multi-endpoint race conditions.

### LAB: Authentication bypass via flawed state machine
Turn on the Intercept function for the whole login process.
Forward the `POST /login` request and drop the `GET /role-selector`. Now visit the `/admin` to see the admin panel and delete user `carlos`.

### LAB: Flawed enforcement of business rules
Notice the coupon are tied to session, which means for the same session each coupon is only used once (`NEWCUST5` and `SIGNUP30`).
To bypass this, first use the 2 coupons when logged in and sign out and use them again. Keep doing that process until we reach a price smaller than $100 and place order.

### LAB: Infinite money logic flaw
Notice that we can use the `SIGNPUP30` coupon for every order (even if it was used in the previous order). Which means we can make \$3 profit per gift-card.
Run a macro to add the gift-card to cart $\to$ apply the coupon $\to$ place order $\to$ get the gift-card value $\to$ redeem the gift-card.
Here is how to configure the macro
1. Click `Settings` in the top toolbar. The `Settings` dialog opens.
2. Click `Sessions`. In the `Session handling rules` panel, click `Add`. The `Session handling rule editor` dialog opens.
3. In the dialog, go to the `Scope` tab. `Under URL scope`, select `Include all URLs`.
4. Go back to the `Details` tab. Under `Rule actions`, click `Add` > `Run a macro`. Under `Select macro`, click `Add` again to open the `Macro Recorder`.
Select the following sequence of requests:

        POST /cart
        POST /cart/coupon
        POST /cart/checkout
        GET /cart/order-confirmation?order-confirmed=true
        POST /gift-card
        Then, click OK. The Macro Editor opens.

5. In the list of requests, select `GET /cart/order-confirmation?order-confirmed=true`. Click `Configure item`. In the dialog that opens, click `Add` to create a custom parameter. Name the parameter `gift-card` and highlight the gift card code at the bottom of the response. Click `OK` twice to go back to the `Macro Editor`.
6. Select the `POST /gift-card` request and click `Configure item` again. In the `Parameter handling` section, use the drop-down menus to specify that the `gift-card` parameter should be derived from the prior response (response 4). Click `OK`.
7. In the `Macro Editor`, click `Test macro`. Make sure the process runs smoothly.
8. Send the `GET /my-account` request to `Burp Intruder`. Make sure that `Sniper attack` is selected.
8. In the `Payloads` side panel, under `Payload configuration`, select the payload type `Null payloads`. Choose to generate 412 (= (1337 - 100) / 3) payloads.
9. Click on `Resource pool` to open the `Resource pool` side panel. Add the attack to a resource pool with the `Maximum concurrent requests` set to `1`. Start the attack.
10. When the attack finishes, we will have enough store credit to buy the jacket and solve the lab.

### LAB: Authentication bypass via encryption oracle
First look at the comment function. When we submit a comment with an invalid email format, we got a notification indicating: `Invalid email: pucavv`. Also, a cookie: `notification=ZfhkAWrl9LusCCHYHLe1FLL8PeTyL8klfzidEnbgd9U%3d` is set. Changing the cookie will affect the notification itself $\to$ the `notification` cookie is the encrypted version of `Invalid email: pucavv`. We can make use of this function to encrypt or decrypt as we want.
Try decrypt the cookie `stay-logged-in=YhsWOoH9Wf4sm3FjkWFp47h4tjB5Olq3AOEyfCnYyo4%3d` by sending this request:

    GET /post?postId=4 HTTP/2
    Cookie: notification=YhsWOoH9Wf4sm3FjkWFp47h4tjB5Olq3AOEyfCnYyo4%3d

The decrypted version is: `wiener:1741266589310`. Now to access the admin panel, we need the encrypted version of `administrator:1741266589310`. Try encrypting it by sending this request:

    POST /post/comment HTTP/2

    csrf=TyGj3tNQgvI94Cx9p3Gdv5wfMbK5HWUz&postId=9&comment=ascas&name=ascsac&email=administrator:1741266589310&website=http://aha.com

Instead of getting the encrypted version of `administrator:1741266589310`, the server first append this 23 characters string `Invalid email address: ` before our string and then encrypt it. Try removing the first 23 bytes of the encrypted version (use Decoder: URL decode it $\to$ Base64 decode it, select the first 23 characters $\to$ `Delete selected byte`, Base64 encode it $\to$ URL encode it) and decrypt it using this request:

    GET /post?postId=4 HTTP/2
    Cookie: notification=%31%65%4b%77%39%6b%69%76%49%33%67%57%69%50%54%51%69%6c%71%43%49%6a%71%4b%30%78%76%63%2b%49%76%75%5a%53%31%37%4b%56%59%31%55%6e%72%50%2f%51%44%75%57%5a%54%71%59%39%77%3d

Now we got an error indicating:

    Input length must be multiple of 16 when decrypting with padded cipher

This suggested that the server is using block cipher with block size = 16 bytes. Therefore, we need to construct a string which size is a multiple of 16 and the string after cutting the `Invalid email address: ` part would still has a size that is a multiple of 16:

    'zzzzzzzzzadministrator:1741266589310     '

Now encrypt this string (copy the string inside the quotes), cut the first 32 bytes using the same method as described above, use it as the value for the cookie `stay-logged-in`, remove the `session` cookie to successfully acces the admin account.

### LAB: Bypassing access controls using email address parsing discrepancies
Read [this article](https://portswigger.net/research/splitting-the-email-atom) to understand the concept.
Construct a email like this: 

    =?utf-7?q?attacker&AEA-exploit-0a71000a047150308263379a018f0032.exploit-server.net&ACA-?=@ginandjuice.shop

This tricks the server into believing that this is a valid email address (ending in `@ginandjuice.shop`). On the other hand, the mail server interprets it as `attacker@exploit-0a71000a047150308263379a018f0032.exploit-server.net` (`&AEA-` and `&ACA-` are UTF-7 version of `@` and ` `, the `@ginandjuice.shop` is ignored by the space character ` `). Therefore, the attacker receives the confirmation email and successfully have access to the admin panel.