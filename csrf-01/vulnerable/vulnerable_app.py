from flask import Flask, render_template, request, redirect, url_for, session
import requests

app = Flask(__name__)
app.secret_key = 'your_secret_key'

@app.route('/')
def home():
    logged_in = 'access_token' in session
    return render_template('home.html', logged_in=logged_in)

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/callback')
def callback():
    code = request.args.get('code')
    response = requests.post('http://localhost:5050/token', data={
        'grant_type': 'authorization_code',
        'code': code,
        'client_id': 'clientid00',
        'client_secret': 'clientsecret11'
    })

    if response.status_code != 200:
        return "Error: Invalid authorization code.", 401

    access_token = response.json()['access_token']
    session['access_token'] = access_token
    return redirect(url_for('home'))

@app.route('/update_email', methods=['POST'])
def update_email():
    access_token = session.get('access_token')
    if not access_token:
        return "Error: Invalid access token.", 401

    new_email = request.form.get('new_email')
    if not new_email:
        return "Error: Invalid email.", 400

    # Here, you would normally update the email in the database.
    # For demonstration purposes, we will just print the new email.
    print(f"New email: {new_email}")

    return redirect(url_for('profile'))


@app.route('/logout')
def logout():
    session.pop('access_token', None)
    return redirect(url_for('home'))

@app.route('/profile')
def profile():
    access_token = session.get('access_token')
    if not access_token:
        return redirect(url_for('login'))

    response = requests.get(f'http://localhost:5050/userinfo?access_token={access_token}')
    if response.status_code != 200:
        return "Error: Invalid access token.", 401

    user_data = response.json()
    return render_template('profile.html', user_data=user_data)

if __name__ == '__main__':
    app.run(debug=True, port=8080)
