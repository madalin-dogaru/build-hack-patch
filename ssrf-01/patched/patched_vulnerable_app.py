from flask import Flask, request, abort
import requests
from urllib.parse import urlparse

app = Flask(__name__)

ALLOWED_DOMAINS = {'http://localhost:8000'}

def is_valid_url(url):
    parsed_url = urlparse(url)
    return parsed_url.scheme in {'http', 'https'} and parsed_url.hostname in ALLOWED_DOMAINS

@app.route('/fetch', methods=['GET'])
def fetch_url():
    url = request.args.get('url')
    if not is_valid_url(url):
        abort(400, 'Invalid URL')
    response = requests.get(url)
    return response.content

if __name__ == '__main__':
    app.run(debug=True)
