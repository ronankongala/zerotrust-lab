import os
import ssl

from flask import Flask, jsonify

CERT_DIR = os.environ.get("CERT_DIR", "/certs")
TLS_CERT = os.environ.get("TLS_CERT", f"{CERT_DIR}/inventory.crt")
TLS_KEY = os.environ.get("TLS_KEY", f"{CERT_DIR}/inventory.key")
TLS_CA = os.environ.get("TLS_CA", f"{CERT_DIR}/ca.crt")


def mtls_context():
    """Serve TLS with our own cert and refuse callers the lab CA didn't sign."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=TLS_CERT, keyfile=TLS_KEY)
    context.load_verify_locations(cafile=TLS_CA)
    # What makes this mutual rather than one-way: without CERT_REQUIRED the
    # server would happily complete a handshake with an anonymous client.
    context.verify_mode = ssl.CERT_REQUIRED
    return context


app = Flask(__name__)

INVENTORY = [
    {"sku": "widget", "on_hand": 42},
    {"sku": "gizmo", "on_hand": 7},
    {"sku": "sprocket", "on_hand": 130},
]


@app.get("/health")
def health():
    return jsonify(service="inventory", status="ok")


@app.get("/inventory")
def inventory():
    return jsonify(inventory=INVENTORY)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, ssl_context=mtls_context())
