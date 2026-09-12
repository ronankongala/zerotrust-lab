import os
import ssl

from flask import Flask, jsonify

CERT_DIR = os.environ.get("CERT_DIR", "/certs")
TLS_CERT = os.environ.get("TLS_CERT", f"{CERT_DIR}/orders.crt")
TLS_KEY = os.environ.get("TLS_KEY", f"{CERT_DIR}/orders.key")
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

ORDERS = [
    {"id": 1, "item": "widget", "qty": 2},
    {"id": 2, "item": "gizmo", "qty": 1},
    {"id": 3, "item": "sprocket", "qty": 5},
]


@app.get("/health")
def health():
    return jsonify(service="orders", status="ok")


@app.get("/orders")
def orders():
    return jsonify(orders=ORDERS)


@app.delete("/orders/<int:order_id>")
def delete_order(order_id):
    """Only ever reached through the gateway, which has already had OPA confirm
    the caller holds the manager role."""
    for index, order in enumerate(ORDERS):
        if order["id"] == order_id:
            return jsonify(deleted=ORDERS.pop(index), remaining=len(ORDERS))
    return jsonify(error="not_found", detail=f"no order {order_id}"), 404


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, ssl_context=mtls_context())
