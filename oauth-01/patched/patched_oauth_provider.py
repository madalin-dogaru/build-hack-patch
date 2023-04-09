from flask import Flask, request, jsonify, render_template_string, redirect
from flask_cors import CORS 
import uuid, hashlib


AUTHORIZATION_CODES = {}

app = Flask(__name__)
CORS(app) 

USERS = {
    "admin": "856f08f94e3316872671e02d3761ac2b2a9bb48e55957b094fc261a6e0d79c13",
    "alex": "46d37c056327a2437590b3f61879e12eaeea8beabf1dcb4860df6483411d056e",
}

CLIENT_ID = "clientid00"
CLIENT_SECRET = "clientsecret11"

# Step 1: Create a dictionary to store access tokens and their corresponding user data
TOKENS = {}

@app.route('/authorize', methods=['GET'])
def authorize():
    client_id = request.args.get('client_id')
    redirect_uri = request.args.get('redirect_uri')
    response_type = request.args.get('response_type')
    state = request.args.get('state')
    if response_type != "code":   
        return "Invalid response_type", 400

    return render_template_string('''
        <form method="POST" action="{{url_for('issue_code')}}">  
            <input type="hidden" name="client_id" value="{{client_id}}">
            <input type="hidden" name="redirect_uri" value="{{redirect_uri}}">
            <input type="hidden" name="state" value="{{state}}">
            <label>Username: <input type="text" name="username"></label>
            <label>Password: <input type="password" name="password"></label>
            <button type="submit">Authorize</button>
        </form>
    ''', client_id=client_id, redirect_uri=redirect_uri, state=state)



@app.route('/issue_token', methods=['POST'])
def issue_token():
    client_id = request.form.get('client_id')
    redirect_uri = request.form.get('redirect_uri')
    state = request.form.get('state')
    username = request.form.get('username')
    password = request.form.get('password')

    # Check if the username exists in USERS and if the password matches
    if username not in USERS or USERS[username] != hashlib.sha256(password.encode()).hexdigest():
        return "Invalid username or password", 401

    access_token = str(uuid.uuid4())
    TOKENS[access_token] = {
        "username": username,
        "email": f"{username}@example.com",
    }

    return redirect(f"{redirect_uri}?access_token={access_token}&token_type=Bearer&state={state}")


@app.route('/issue_code', methods=['POST'])
def issue_code():
    client_id = request.form.get('client_id')
    redirect_uri = request.form.get('redirect_uri')
    state = request.form.get('state')
    username = request.form.get('username')
    password = request.form.get('password')

    # Check if the username exists in USERS and if the password matches
    if username not in USERS or USERS[username] != hashlib.sha256(password.encode()).hexdigest():
        return "Invalid username or password", 401

    auth_code = str(uuid.uuid4())
    AUTHORIZATION_CODES[auth_code] = {
        "username": username,
    }

    return redirect(f"{redirect_uri}?code={auth_code}&state={state}")

@app.route('/token', methods=['POST'])
def token():
    client_id = request.form.get('client_id')
    client_secret = request.form.get('client_secret')
    redirect_uri = request.form.get('redirect_uri')
    code = request.form.get('code')
    grant_type = request.form.get('grant_type')

    if grant_type != "authorization_code" or code not in AUTHORIZATION_CODES:
        return "Invalid grant_type or code", 400

    if client_id != CLIENT_ID or client_secret != CLIENT_SECRET:
        return "Invalid client_id or client_secret", 401

    access_token = str(uuid.uuid4())
    username = AUTHORIZATION_CODES[code]["username"]  # Get the correct user for the given authorization code
    # Store the access token and user data in the dictionary
    TOKENS[access_token] = {
        "username": username,
        "email": f"{username}@example.com",
    }
    return jsonify({"access_token": access_token, "token_type": "Bearer"})


@app.route('/userinfo', methods=['GET'])
def userinfo():
    access_token = request.args.get('access_token')
    if not access_token:
        return "Invalid access_token", 401

    user_data = TOKENS.get(access_token)
    if not user_data:
        return "Invalid access_token", 401

    return jsonify(user_data)

if __name__ == '__main__':
    app.run(debug=True, port=5050)

