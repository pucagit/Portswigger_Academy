# Information Disclosure
Information disclosure, also known as information leakage, is when a website unintentionally reveals sensitive information to its users.

**Common sources of information disclosure:**
- Files for web crawlers: `/robots.txt` and `/sitemap.xml`
- Directory listings: Web servers can be configured to automatically list the contents of directories that do not have an index page present
- Developer comments
- Error messages
- Debugging data
- User account pages
- Source code disclosure via backup files
- Information disclosure due to insecure configuration: such as the use of HTTP `TRACE` method
- Version control history: try access this by browsing to `/.git`

### LAB: Information disclosure in error messages
Try an invalid path: `/product?productId=1a` and got the error message leaking the version number of the used framework.

### LAB: Information disclosure on debug page
Crawl through the page source and found this suspicious comment:

    <!-- <a href=/cgi-bin/phpinfo.php>Debug</a> -->

Visit `/cgi-bin/phpinfo.php` and use `Ctrl+F` to look for the keyword `key` and submit the solution.

### LAB: Source code disclosure via backup files
Visit `/robots.txt` notice the suspicious directory: `/backup`.
Visit `/backup` got the directory listing page and found `ProductTemplate.java.bak`.
Go to `/backup/ProductTemplate.java.bak` to find the database password.

### LAB: Authentication bypass via information disclosure
Try visit `/admin` and got the response indicating: 

    Admin interface only available to local users

Repeat the request, but this time using `TRACE` and found a suspicious custom header: `X-Custom-Ip-Authorization` containing my public IP address. This time add this custom header but with a local IP address and make a `GET` request to `/admin`:

    X-Custom-Ip-Authorization: 127.0.0.1

Successfully got in the admin interface. Perform `POST /admin/delete?username=carlos` with the custom header to delete user `carlos`.

### LAB: Information disclosure in version control history
Visit `/.git` and find that the version control system is present and accessible.
Use WSL and download this directory using:

    wget -r https://0aee00dd0383f362831b2d8600d10071.web-security-academy.net/.git

Open VS Code and navigate to the location that was downloaded and open `Source Control` to view the commits and retrieve the admin's password.