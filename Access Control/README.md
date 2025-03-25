# Access Control
Access control is the application of constraints on who or what is authorized to perform actions or access resources. In the context of web applications, access control is dependent on authentication and session management:
- **Authentication** confirms that the user is who they say they are.
- **Session management** identifies which subsequent HTTP requests are being made by that same user.
- **Access control** determines whether the user is allowed to carry out the action that they are attempting to perform.

## Models
- **Programmatic access control:** a matrix of user privileges is stored in a database or similar and access controls are applied programmatically with reference to this matrix.
- **Discretionary access control (DAC):** access to resources or functions is constrained based upon users or named groups of users. Owners of resources or functions have the ability to assign or delegate access permissions to users.
- **Mandatory access control (MAC):** centrally controlled system of access control in which access to some object (a file or other resource) by a subject is constrained, users and owners of resources have no capability to delegate or modify access rights for their resources.
- **Role-based access control (RBAC):** named roles are defined to which access privileges are assigned. Users are then assigned to single or multiple roles.

## Insecure Direct Object Reference (IDOR)
This type of vulnerability arises where user-controller parameter values are used to access resources or functions directly.

### LAB: Unprotected admin functionality
Found the `/administrator-panel` location in the `/robots.txt`. Visit the admin panel and delete user `carlos`.

### LAB: Unprotected admin functionality with unpredictable URL
Found the `/admin-qc3cr7` location in the script embedded in the page source: 

    <script>
        var isAdmin = false;
        if (isAdmin) {
            var topLinksTag = document.getElementsByClassName("top-links")[0];
            var adminPanelTag = document.createElement('a');
            adminPanelTag.setAttribute('href', '/admin-qc3cr7');
            adminPanelTag.innerText = 'Admin panel';
            topLinksTag.append(adminPanelTag);
            var pTag = document.createElement('p');
            pTag.innerText = '|';
            topLinksTag.appendChild(pTag);
        }
    </script>

### LAB: User role controlled by request parameter
Login as normal user `wiener:peter`. Found a cookia named `Admin:False`.
Change the cookie to `Admin:True` and visit `/admin` to successfully delete user `carlos`.

### LAB: User role can be modified in user profile
Find that the `changeEmail.js` update data using JSON format. 
Send the `POST /my-account/change-email` request containing this body:

    {
        "email":"haha123@gmail.com",
        "roleid":2
    }

As suggested in the lab's description (admin has `roleid=2`), normal user `wiener:peter` has now access to the admin panel and can delete user `carlos`. 

### LAB: URL-based access control can be circumvented
This website has an unauthenticated admin panel at /admin, but a front-end system has been configured to block external access to that path. However, the back-end application is built on a framework that supports the `X-Original-URL` header.
Visit the admin panel using this request:

    GET / HTTP/2
    X-Original-URL: /admin

Found the URL to delete user `carlos`. Send this request to successfully delete the user:

    GET /?username=carlos HTTP/2
    X-Original-URL: /admin/delete

### LAB: Method-based access control can be circumvented
Login as user `wiener:peter`.
Try `POST /admin-roles HTTP/2` and got the `401 Unauthorized` response. 
Use `Change request method` in Burp and send the request `GET /admin-roles?username=wiener&action=upgrade HTTP/2`.
Notice the admin panel appears $\to$ successfully upgrade user's role to admin.

### LAB: User ID controlled by request parameter
Visit `/my-account?id=carlos` to obtain the API key and submit it.

### LAB: User ID controlled by request parameter, with unpredictable user IDs
Find a post that belongs to user `carlos` and obtain his `id` (`ffdf22e1-12a7-45ca-a9ba-6f8ed11f9875`).
Visit `my-account?id=ffdf22e1-12a7-45ca-a9ba-6f8ed11f9875` to optain the API key and submit it.

### LAB: User ID controlled by request parameter with data leakage in redirect
Visit `/my-account?id=carlos` and got the redirect response. But inside this response leaks the API key of `carlos`. Obtain it and submit the key.

### LAB: User ID controlled by request parameter with password disclosure
Visit `/my-account?id=administrator` and inspect the password field to obtain the admin's password. 
Login to the admin's account and delete user `carlos`.

### LAB: Insecure direct object references
Send a message and then click on `View Transcript`. Notice the `GET /download-transcript/2.txt` request. 
Do the same actions again and now observe the `GET /download-transcript/3.txt` request. 
Guess that the transcripts are text files assigned a filename containing an incrementing number. Use `Burp Repeater` and send the `GET /download-transcript/1.txt` request and retrieve carlos's password. 

### LAB: Multi-step process with no access control on one step
Login using the admin's credential and send the last step of upgrading a user to `Burp repeater`:

    POST /admin-roles HTTP/2
    Cookie: session=YmBy6Z1pImxNNtHI8se6f8ZG09rwYGCs
    action=upgrade&confirmed=true&username=carlos

Now login using `wiener:peter` credential, take the session cookie (`LC20caC6BJtECbzcilx0mufA4hA8GpkN`) and send this request:

    POST /admin-roles HTTP/2
    Cookie: session=LC20caC6BJtECbzcilx0mufA4hA8GpkN
    action=upgrade&confirmed=true&username=wiener

Successfully upgrade user `wiener:peter` without using admin's credential.

### LAB: Referer-based access control
Same as above lab but the server now check for the `Referer` header to be coming from `/admin`.