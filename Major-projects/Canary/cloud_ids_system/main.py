# in main.py
from flask import Flask

app = Flask(__name__)

@app.route('/')
def hello():
    print("Flask server received a request!")
    return "Congratulations, your setup is working! ✅"

if __name__ == '__main__':
    print("Starting Flask test server at http://127.0.0.1:5000")
    app.run(port=5000)