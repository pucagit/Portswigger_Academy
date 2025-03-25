## 2FA broken logic

**Key:** Successfully login only by needing to brute-force the `mfa-code`, without knowing the actual password.

> **Solve**:
>
> - Use the given credentials to get the request to the /login2 page
> - Find that, only the cookie `verify` and the `mfa-code` is checked to login
> - Change the cookie to `verify: carlos` and brute-force the `mfa-code` using _Sniper attack_.

## 2FA bypass using a brute-force attack

**Key:** Same as above scenario but with additional security layer: log out after 2 wrong `mfa-code`. So we need to apply a macro for the brute-force attack to redo all the process.

> **Solve**:
>
> - Go to _Settings_ $\to$ *Session* $\to$ *Add Session handling rules* $\to$ *Add Rule actions* $\to$ *Run a macro* $\to$ *Add the requests (GET /login, POST /login, GET /login2)*. In *Scope* $\to$ *URL Scope* $\to$ *Include all URLs*.
> - In *Resource Pool* $\to$ *Create new resource pool* $\to$ *Maximum concurrent requests: 1*
> - Run the _Sniper attack_ using _Brute forcer_ payload for the `mfa-code`.
