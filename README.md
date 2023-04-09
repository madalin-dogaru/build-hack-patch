# Build-Hack-Patch
### Table of Contents
- [SSRF-01 exercise](https://github.com/madalin-dogaru/build-hack-patch/blob/master/README.md#ssrf-01---server-side-request-forgery) 
- [CSRF-01 exercise](https://github.com/madalin-dogaru/build-hack-patch#csrf-01---cross-site-request-forgery)

This series of tutorials aim to introduce common cybersecurity vulnerabilities and their fixes. It is designed for beginners and follows a three-step process for each vulnerability:

1. Build a vulnerable application.
2. Exploit the vulnerability.
3. Patch the vulnerability.

### Prerequisites
-------------------
Install the required dependencies:   
`pip install -r requirements.txt`

## SSRF-01 - (Server-Side Request Forgery)

### Build It.
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


### Hack It.
-------------------
1. Start both apps:
```
python3 vulnerable_app.py
python3 third_party_app.py
```
```
 * Serving Flask app 'vulnerable_app'
 * Debug mode: on
 * Running on http://127.0.0.1:5000
```
```
Serving on port 8000
```
Note the port each of the apps are serving on, and to avoid confusion, lets use `127.0.0.1` for vulnerable_app and `localhost` for third_party_app.   

When looking at vulnerable_app.py code we see it uses a `/fetch` path, and it gets the `url` value, fetches the information afrom that URL and then returns its content.   

2. Lets see if we can fetch the information from https://github.com :   
`http://127.0.0.1:5000/fetch?url=https://github.com`   
When running this in the browser we notice the github.com page loads, but when click on "Princing" from the page's top menu, we get 404 not found. This is because it just retrieves the content from github.com, and then it shows it in the browser, nothing more. 

3. The third_party_app.py is a simple http python server that serves the files in its runtime folder.    
 Lets start it:
 `python3 third_party_app.py`

4. Going back to our attacker, we mentioned that he doesnt have direct access to third_party_app so what he will try to do is to use vulnerable_app to
  make a request to third_party_app:   
  `http://127.0.0.1:5000/fetch?url=http://localhost:8000`   
  As you can see, because there is no URL whitelisting we can make requests to another server from the company that is on a local server. Now you can see the file structure of third_party_app. Furthermore if any important information is on that server, you can list it and use it to laterally move.   

 5. We see there is a folder .ssh and we list it:    
 `http://127.0.0.1:5000/fetch?url=http://localhost:8000/.ssh/`

 6. Inside it we have a private and a public key so we list them: 
 `http://127.0.0.1:5000/fetch?url=http://localhost:8000/.ssh/id_ed25519`
 `http://127.0.0.1:5000/fetch?url=http://localhost:8000/.ssh/id_ed25519.pub`

 Now an attacker will search for ways to use those keys and laterally move.  
 
 **Additonal Note**: When people use the words build and exploit they reffer to this high level process:   
 1. Find a vulnerability manually. 
 2. Automate the vulnerability. 

 To give you an example, in our case, I added a file called exploit.py. if you look at the code it simply combines the base url `http://127.0.0.1:5000/fetch` + the url you specify in the script and it returns the result. Same thing you did manually, try it out.   


 ### Patch It.
-------------------
 1. Code adjustments:   
 To patch vulnerable_app we need to update its code so it whitelists a specific URL or multiple URLs.Specifically, the code below has only github.com  
 whitelisted and then bellow, it checks if the URL you fed to the url parameter was on the whitelist, otherwise it returns "Bad Request, Invalid URL"

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
This attempt fails as it doesnt pass the whitelist check and the ssh keys are safe.

## CSRF-01 - (Cross-Site Request Forgery)
Occurs when a user is tricked into unknowingly performing an action on a website that they did not intend to perform. In a CSRF attack, the attacker creates a malicious website which holds a link or form that will perform an action on a different website where the user is currently logged into.

### Build It. 

We want to create something to represent this diagram scenario: 
```
+--------------+       +----------------+       +--------------+
|              |  (1)  |                |  (2)  |              |
|   Attacker   +------->  malicious.html +------->   Victim's   |
|              |       |                |       |   Browser    |
+--------------+       +----------------+       +------+-------+
                                                      |
                                                      | (3)
                                                      v
+--------------+       +----------------+       +--------------+
|              |       |                |       |              |
|  OAuth Server|<------| vulnerable_app |<------+  Victim's    |
|              |       |                |       |   Browser    |
+--------------+       +----------------+       +--------------+
```
- oauth_provider.py , OAuth authorization provider. 
- vulnerable_app.py , Application on which the user wants to create an account using the data from OAuth provider
- malicious.html , in real life this would be hosted on the attackers domain and the hacker would send to the user a link that would point to this file which in turn would send a request to the website the user is logged into, with the goal to perform an action. 

Application Functionality:    
The vulnerable_app allows the user to access their account using the data from the oauth_provider. The user grants access to their data by authenticating through the OAuth flow, and the vulnerable_app receives an access token. The vulnerable_app then uses this token to request the user's data from the oauth_provider and provides the user with access to the app based on that information.

- /templates holds the .html pages for profile, home and login. 


### Hack It. 
1. Start both oauth_provider.py and vulnerable_app.py in 2 separate terminal windows. Note that changes to the files or information on whats requested/received in the apps is outputed in the terminal. 

2. Go to http://127.0.0.1:8080 and login with either "admin": "romania" or "alex": "bucharest" (user:password). Now you are logged in and see your profile data.In the terminal window where you started, notice that there is a line similar to this one: 
```
"GET /userinfo?access_token=b0347ee4-b6cc-4c24-bb5f-3df5346ebecb HTTP/1.1" 200 -
``` 
The access_token is generated each time the user logs in, by the OAuth provider. Read a bit about it. 

3. To hack the user, an attacker would first choose and research the website the user loggs into, would then create a file more complex but with the same principle as malicious.html and then send the link to the user. Overall the steps are: 

- The attacker creates the malicious.html file and hosts it on a different website.
- The victim visits the malicious website (either by clicking on a link or being redirected), and the malicious code in malicious.html is executed in the victim's browser.
- The victim's browser sends a request to the vulnerable_app web application, which includes the authentication information (access token) for the victim. The vulnerable_app processes the request and performs the action specified in the malicious.html code, in our case, changing the victim's email address.

4. Run malicious.html after logging in to the vulnerable_app. You will be redirected to /profile and in the terminal window where you started vulnerable_app.py you will see outputed: `New email: hacker@example.com`. I didnt create a database for this exercise to keep complexity low but in a real world scenario `127.0.0.1 - - [07/Apr/2023 18:59:54] "POST /update_email HTTP/1.1" 302 -` which is visible in the terminal would have ment the hacker tricked the victim to change his application email to his email. Next, the attacker would reset the user's password, log him out and take over his account. 

### Patch It. 
One protection for CSRF are CSRF tokens.

1. Patch vulnerable_app.py to include the necessary imports and initialize the CSRF protection:   
```
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_wtf.csrf import CSRFProtect
import requests

app = Flask(__name__)
app.secret_key = 'your_secret_key'
csrf = CSRFProtect(app)
```
2. Patch our update_email route to check for the CSRF token:
```
@app.route('/update_email', methods=['POST'])
def update_email():
    access_token = request.form.get('access_token')
    new_email = request.form.get('new_email')

    if not access_token or not new_email:
        return "Error: Invalid access token or email.", 401

    response = requests.post('http://localhost:5050/update_email', json={
        'access_token': access_token,
        'new_email': new_email
    })

    if response.status_code != 200:
        return "Error: Invalid access token or email.", 401

    flash("Email updated successfully.")
    return redirect(url_for('profile'))
```
 3. Patch our profile.html template to include the CSRF token in the form:
```
<form action="{{ url_for('update_email') }}" method="post">
    {{ csrf_token() }}
    <label for="new_email">New email:</label>
    <input type="email" name="new_email" id="new_email" required>
    <input type="hidden" name="access_token" value="{{ access_token }}">
    <input type="submit" value="Update Email">
</form>
```
With these changes in place, the server will now expect a valid CSRF token to be submitted with each update_email request. This effectively prevents CSRF attacks, as the attacker cannot forge a valid CSRF token without having access to the server-generated token value.

Try the same attack as before and you will be getting an error about not having the correct CSRF token. 

## OAuth-01 - (State Parameter Logic Flaw)
A logic flaw, is a mistake or oversight in the design or implementation of an application's code that leads to unintended behavior or security vulnerabilities. It typically arises when the code does not properly handle certain conditions, user inputs, or data flows, causing the application to function incorrectly or in a way that the developer did not intend.

### Build It. 
We have a simple **vulnerable_app.py** with 2 users, alex and admin, who can authorize the vulnerable_app against **oauth_provider.py** to get their profile information.

### Hack It.
Before we begin, start both applications.

1. Go to the Vulnerable App's main page, http://localhost:8080 and click on the login button. This will redirect you to the OAuth provider's /authorize endpoint:
```
http://localhost:5050/authorize?client_id=clientid00&response_type=token&state=state&redirect_uri=http://localhost:8080/callback
```
2. On the authorization page, enter Alex's credentials (alex:bucharest) and click "Authorize".
3. The OAuth provider's /issue_token endpoint was called with the following POST request (use Burp to intercep it):
```
POST /issue_token HTTP/1.1
Host: localhost:5050
..[code snipet]
client_id=clientid00&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fcallback&state=state&username=alex&password=bucharest

```
Set in the above POST the state parameter to "admin"(state=state), which represents the username of the admin account and click send with Burp's repeater.


4. The OAuth provider will issue an access token and will redirect you back to the Vulnerable App's `/callback` endpoint with the access token and state parameter in the URL:
```
http://localhost:8080/callback?access_token=a5bf2e40-61aa-4956-a743-7daf0c7eb30f&token_type=Bearer&state=admin

```
5. The Vulnerable App will then call the OAuth provider's `/userinfo` endpoint with the access token you received but because we dont have a more complex app, lets do manually what vulnerable_app would have done. Go in the browser and access this URL: 
```
http://localhost:5050/userinfo?access_token=a5bf2e40-61aa-4956-a743-7daf0c7eb30f
```

6. Due to the authentication bypass vulnerability, the state parameter was set to "admin" in step 3, causing the oauth_provider.py to believe provide you admin's information. 
```
{
  "email": "admin@example.com",
  "username": "admin"
}
```

### Patch It.
This are the steps that we performed to patch the logic flaw. 

1. Store the 'state' parameter in the session: In the `/callback` function of the vulnerable_app.py script, the 'state' parameter from the request was not checked or stored. To fix this, we stored the 'state' parameter in the session before redirecting the user to the oauth_provider.py. This way, the application can later verify if the received state matches the stored state.   

2. Check the 'state' parameter in the oauth_provider.py: In the oauth_provider.py script, we checked the 'state' parameter received in the `/authorize` endpoint. We modified the function to only return the authorization form if the 'state' parameter matches the expected value ('state' in this case). If the 'state' does not match, an error message is returned instead.   

3. Return the 'state' parameter with the authorization code: In the `/issue_code` function of the oauth_provider.py script, we added the 'state' parameter to the redirect URL. This way, the client application receives the 'state' parameter along with the authorization code.   

4. Check the 'state' parameter in the client application: In the `/callback` function of the `vulnerable_app.py script`, we added a check for the 'state' parameter received from the OAuth provider. If the 'state' parameter does not match the stored 'state' in the session, an "Access denied" message is returned, and the user is not authenticated.    

5. Remove hardcoded values: In the /token function of the `oauth_provider.py` script, the 'code' value was hardcoded. We modified the function to check if the 'code' parameter exists in the `AUTHORIZATION_CODES` dictionary. If the 'code' is not found in the dictionary, an "Invalid grant_type or code" error message is returned.   

By implementing these changes, we have ensured that the 'state' parameter is correctly checked, preventing attackers from bypassing authentication by manipulating the 'state' value.
