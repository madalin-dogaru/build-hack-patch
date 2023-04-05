# Build-Hack-Patch

The goal of this repo is to take a complete cybersecurity new commer from zero, show him all the common vulnerabilities and how to fix them. 

I will start with some very simple exercises so you understand the principle first. Each exercise will tackle one vulnerability, presented in the way I would have wanted to learn them when I started looking into cybersecurity. Once all vulnerabilities are covered, I will create more complicated exercises. 

Hacking means to trully understand the target before you attempt to hack it, but also to be able to adapt your attack if its not working one month later. 

Each exercise will have the following structure: 
1. Build a vulnerable application. 
2. Exploit the application.
3. Patch the application so its not vulnerable anymore.

For all the exercises to work please install the required dependencies: 
`pip install -r requirements.txt`

## SSRF-01 - (Server-Side Request Forgery)

SSRF is a security vulnerability that occurs in web Apps. Essentially, it allows an attacker to make requests to other systems or services that a web application has access to.
Usually the attacker doesnt have access to or knows that application B exists but because application A is vulnerable to SSRF he can exploit it to get access to application B. 
```
+--------+     +----------+     +-----------------+
| Hacker +-----> Vuln_App +-----> Third_Party_App |
+--------+     +----------+     +-----------------+
```
**Scenario for vulnerable app:**
1. vulnerable_app.py is web server that is vulnerable to SSRF. 
2. third_party_app.py is a server that vulnerable_app.py uses to process some data.
3. In our imagined scenario you cant access third_party_app.py directly, lets say because its on a local server. 
4. Goal: get the .ssh private key from third_party_app.py


#### Exploitation
1. Start the vulnerable app and the third party app: 
`python3 vulnerable_app.py`
```
 * Serving Flask app 'vulnerable_app'
 * Debug mode: on
 * Running on http://127.0.0.1:5000
```

`python3 third_party_app.py`
```
Serving on port 8000
```
Note the ports, each of the apps are serving on, and to avoid confusion, lets use `127.0.0.1` for vulnerable_app and `localhost` for third_party_app. 

When looking at vulnerable_app.py we see it uses a `/fetch` path, and it gets the `url` value, fetches the information afrom that URL and then returns its content. 
1. Lets see if we can fetch the information from https://github.com :
`http://127.0.0.1:5000/fetch?url=https://github.com`

When running this in the browser we notice the github.com page loads, but when click on "Princing" from the page's top menu, we get 404 not found. This is because it just retrieves the content from github.com, and then it shows it in the browser, nothing more. 

2. The third_party_app.py is a simple http python server that serves the files in its runtime folder.    
 Lets start it:
 `python3 third_party_app.py`

 3. Going back to our attacker, we mentioned that he doesnt have direct access to third_party_app so what he will try to do is to use vulnerable_app to make a request to third_party_app:
 `http://127.0.0.1:5000/fetch?url=http://localhost:8000`

 As you can see, because there is no URL whitelisting we can make requests to another server from the company that is on a local server. Now you can see the file structure of third_party_app. Furthermore if any important information is on that server, you can list it and use it to laterally move. 

 4. We see there is a folder .ssh and we list it:    
 `http://127.0.0.1:5000/fetch?url=http://localhost:8000/.ssh/`

 5. Inside it we have a private and a public key so we list them: 
 `http://127.0.0.1:5000/fetch?url=http://localhost:8000/.ssh/id_ed25519`
 `http://127.0.0.1:5000/fetch?url=http://localhost:8000/.ssh/id_ed25519.pub`

 Now an attacker will search for ways to use those keys and laterally move.    
 When people use the words build and exploit they reffer to this high level process:   
 1. Find a vulnerability manually. 
 2. Automate the vulnerability. 

 To give you an example, in our case, I added a file called exploit.py. if you look at the code it simply combines the base url `http://127.0.0.1:5000/fetch` + the url you specify in the script and it returns the result. Same thing you did manually. 


 #### Patching

 1. Code adjustments:   
To patch vulnerable_app we need to update its code so it whitelists a specific URL or multiple URLs.
Specifically, the code below has only github.com whitelisted and then bellow, it checks if the URL you fed to the url parameter was on the whitelist, otherwise it returns "Bad Request, Invalid URL"

```
ALLOWED_DOMAINS = {'github.com'}

def is_valid_url(url):
    parsed_url = urlparse(url)
    return parsed_url.scheme in {'http', 'https'} and parsed_url.hostname in ALLOWED_DOMAINS
```

2. Testing with the whitelisted domain:   
`http://127.0.0.1:5000/fetch?url=http://github.com`

Github.com is loaded correctly. 

3. Now lets see if we can still access the ssh keys from third_party_app.py. 
`http://127.0.0.1:5000/fetch?url=http://localhost:8000`

This attempt fails as it doesnt pass the whitelist check and the ssh keys are safe `:))`.

