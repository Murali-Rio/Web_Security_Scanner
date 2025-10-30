from flask import Flask, request, send_from_directory, jsonify
import os
import requests
import time
from zapv2 import ZAPv2
from werkzeug.exceptions import BadRequestKeyError

app = Flask(__name__, static_folder="static", static_url_path="")

# --- Configuration ---
ZAP_API_KEY = '3dp5bf7bm41io13cdu36df3cvb'  # Replace with your actual ZAP API key
ZAP_URL = 'http://127.0.0.1:8080'  # Default ZAP API address

# Initialize ZAP client
zap = ZAPv2(apikey=ZAP_API_KEY, proxies={'http': ZAP_URL, 'https': ZAP_URL})

# --- Vulnerability Scan ---
def scan_vulnerabilities(url):
    """Scans a website for vulnerabilities using OWASP ZAP."""
    try:
        print(f"Starting new ZAP session for {url}...")
        zap.core.new_session(name='mysession', overwrite=True)

        print("Accessing target in ZAP...")
        zap.urlopen(url)
        time.sleep(2)

        print("Starting active scan...")
        scan_id = zap.ascan.scan(url)
        while int(zap.ascan.status(scan_id)) < 100:
            print(f"Scan progress: {zap.ascan.status(scan_id)}%")
            time.sleep(5)

        print("Scan completed.")
        alerts = zap.core.alerts(baseurl=url)
        if alerts:
            results = "\n".join([f"Risk: {a['risk']} | Alert: {a['alert']}" for a in alerts])
            return results
        else:
            return "No vulnerabilities found."
    except Exception as e:
        return f"Error during scan: {str(e)}"

# --- Malware Scan (mock) ---
def scan_malware(url):
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            return "No malware found (mock result)."
        else:
            return "Failed to fetch website content."
    except Exception as e:
        return f"Error fetching website: {str(e)}"

# --- Routes ---
@app.route('/')
def index():
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/scan', methods=['POST'])
def scan():
    url = request.form.get('url')
    scan_type = request.form.get('scan_type', 'vulnerability')  # Default type if not provided

    if not url:
        return jsonify(message="Bad Request: Missing required parameter 'url'"), 400

    if scan_type == 'vulnerability':
        scan_result = scan_vulnerabilities(url)
    elif scan_type == 'malware':
        scan_result = scan_malware(url)
    else:
        scan_result = "Invalid scan type selected."

    return f"<h2>Scan Results for {url}</h2><pre>{scan_result}</pre>"

@app.errorhandler(BadRequestKeyError)
def handle_bad_request_error(e):
    return jsonify(message='Bad Request: Missing required parameter'), 400

if __name__ == '__main__':
    app.run(debug=True, port=5000)
