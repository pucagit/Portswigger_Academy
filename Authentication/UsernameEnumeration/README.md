## Username enumeration via subtly different responses

**Key**: find a slightly different response when username is correct: _Invalid username or password_ instead of _Invalid username or password._ as in other cases

> **Solve**:
>
> - Start a sniper attack with a list of given usernames
> - After attack is completed $\rightarrow$ go to **Settings** $\rightarrow$ under **Grep - Extract** click **Add** and mark the `Invalid username or password.`
> - Sort the error column to find onee response with different warning $\rightarrow$ that is the username to find.
> - Brute-force the password with the found username.

## Username enumeration via response timing

**Key**: change the `X-Forwarded-For` header with each brute-force attack to bypass IP-based brute-force protection. Notice that one of the response times was significantly longer than the others.

> **Solve**:
>
> - Start a _pitchfork attack_ with _payload 1_ as the last octet of the IP address in `X-Forwarded-For` header in range of $1 \to 100$; _payload 2_ as the list of usernames
> - Set the password to a long string (about 100 characters) to make response time longer $\to$ the longest response time received is the username to find
> - Brute-force the password with the found username.

## Broken brute-force protection, IP block

**Key**: After each brute-force trial, login using an authenticated account (`wiener:peter`) to reset the the counter for the number of failed attempts resets mechanism.

> **Solve**:
>
> - Start a _pitchfork attack_ with _payload 1_ as the username and _payload 2_ as the password
> - For example:
> - - payload 1 = (wiener, username1, wiener, username2,...);
> - - payload 2 = (peter, password1, peter, password2,...)

## Username enumeration via account lock

**Key**: Find a valid username based on blocking of the account when certain number of failed authentication attempts was made

> **Solve**:
>
> - Use a _Cluster bomb attack_ with _payload 1_ for the list of the username and _payload 2_ using 5 Null payloads (Generate 5 payloads in the configuration)
> - Find the response with `You have made too many incorrect login attempts.` $\to$ that is a valid username
> - Start a _Sniper attack_ to brute-force the corresponding password (notice that when the account is locked out and you enter a correct password, there would be no error messages)

## Broken brute-force protection, multiple credentials per request

**Key**: There is a logic flaw in the login function when handling request in JSON: it accepts the password to be sent as an array and if a correct password appeared in that array $\to$ successfull login.

> **Solve**:
>
> - Paste the password list as an array format in `"password"` parameter
> - Receive response logged in as _carlos_, copy the cookie session in the response and paste it into the browser $\to$ successfull login.
