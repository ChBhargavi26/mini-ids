from flask import Flask, jsonify, render_template
import threading

import alerts
import config
import sniffer


app = Flask(__name__)


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/api/alerts")
def get_alerts():
    return jsonify(alerts.get_alerts())


@app.get("/api/stats")
def get_stats():
    return jsonify({
        "packets": alerts.stats["packets"],
        "alerts": len(alerts.get_alerts())
    })


def start_background_sniffer():
    """
    Run Scapy packet capture in a background thread.
    """
    sniffer.start_sniffer()


if __name__ == "__main__":

    print("===================================")
    print("       MINI IDS DASHBOARD")
    print("===================================")

    # Start packet capture in the background
    sniffer_thread = threading.Thread(
        target=start_background_sniffer,
        daemon=True
    )

    sniffer_thread.start()

    print()
    print(f"Dashboard: http://127.0.0.1:{config.DASHBOARD_PORT}")
    print("Packet sniffer started.")
    print()

    app.run(
        host=config.DASHBOARD_HOST,
        port=config.DASHBOARD_PORT,
        debug=False,
        use_reloader=False
    )