from flask import Flask, request
import requests

app = Flask(__name__)

@app.route('/fetch', methods=['GET'])
def fetch_url():
    url = request.args.get('url')
    response = requests.get(url)
    return response.content

if __name__ == '__main__':
    app.run(debug=True)
