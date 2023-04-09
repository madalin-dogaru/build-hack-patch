from flask import Flask, render_template_string, request, redirect, url_for, session
import requests

app = Flask(__name__)
app.secret_key = 'your_secret_key'

OAUTH_PROVIDER_URL = 'http://localhost:5050'
CLIENT_ID = 'clientid00'

users = {
    'admin': {'username': 'admin', 'email': 'admin@example.com'},
    'alex': {'username': 'alex', 'email': 'alex@example.com'}
}

@app.route('/')
def home():
    logged_in = 'username' in session
    return render_template_string('''
        <h1>Vulnerable App</h1>
        <ul>
            <li><a href="{{ url_for('profile') }}">Profile</a></li>
            <li><a href="{{ url_for('login') }}">Login</a></li>
            {% if logged_in %}
                <li><a href="{{ url_for('logout') }}">Logout</a></li>
            {% endif %}
        </ul>
    ''', logged_in=logged_in)


@app.route('/profile')
def profile():
    if 'username' not in session:
        return redirect(url_for('login'))

    user = users[session['username']]
    return render_template_string('''
        <h1>{{ user.username }}'s Profile</h1>
        <p>Username: {{ user.username }}</p>
        <p>Email: {{ user.email }}</p>
    ''', user=user)

@app.route('/login')
def login():
    return redirect(f"http://localhost:5050/authorize?client_id=clientid00&response_type=token&state=state&redirect_uri=http://localhost:8080/callback")


@app.route('/callback')
def callback():
    access_token = request.args.get('access_token')
    state = request.args.get('state')

    if access_token:
        # Get user information from the /userinfo endpoint
        userinfo_url = f"{OAUTH_PROVIDER_URL}/userinfo?access_token={access_token}"
        response = requests.get(userinfo_url)

        if response.status_code == 200:
            user_data = response.json()
            session['username'] = user_data['username']
            users[session['username']] = user_data
        else:
            return "Error fetching user information", 401

        return redirect(url_for('profile'))
    else:
        return "Access denied", 403


@app.route('/logout')
def logout():
    if 'username' in session:
        session.pop('username')
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True, port=8080)
