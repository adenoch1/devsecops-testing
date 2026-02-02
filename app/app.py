from flask import Flask, jsonify, render_template
import os

app = Flask(__name__)

@app.route("/health")
def health():
    return jsonify(status="ok"), 200

@app.route("/")
def index():
    return render_template("index.html")

if __name__ == "__main__":
    # Secure default: bind only to localhost
    host = os.getenv("FLASK_HOST", "127.0.0.1")

    # Container environments require binding to all interfaces
    if os.getenv("ENV") == "container":
        host = "0.0.0.0"  # nosec B104 - required to expose Flask from Docker container

    port = int(os.getenv("FLASK_PORT", "5000"))

    app.run(host=host, port=port)
