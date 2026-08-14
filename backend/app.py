from flask import Flask, jsonify

app = Flask(__name__)


@app.route("/health")
def health():
    """Health check endpoint. Confirms the NetSentinel backend is running."""
    return jsonify({"status": "ok", "service": "NetSentinel"})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
