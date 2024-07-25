import requests
from flask import Flask
app = Flask(__name__)

@app.route("/")
def hello():
    return "Hello World!"

@app.route("/second_http")
def second_http():
    requests.get("http://www.example.com")
    return "Hello World!"

@app.route("/second_https")
def second_https():
    requests.get("https://www.example.com")
    return "Hello World! (https)"

@app.route("/large")
def large():
    numbers = [str(i) for i in range(1000)]
    resp = ", ".join(numbers)
    return resp

if __name__ == "__main__":
    app.run(ssl_context='adhoc')
