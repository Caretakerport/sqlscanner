from flask import Flask, render_template, request
import requests

app = Flask(__name__)

def check_sqli_vulnerability(url):
    payloads = ["' OR '1'='1", "'; DROP TABLE users;", "1' OR '1'='1'--"]
    vulnerabilities = []

    for payload in payloads:
        test_url = f"{url}?id={payload}"
        response = requests.get(test_url)

        if "error" in response.text.lower():
            vulnerabilities.append(f"SQLi vulnerability detected: {test_url}")

    return vulnerabilities

@app.route("/", methods=["GET", "POST"])
def index():
    vulnerabilities = []

    if request.method == "POST":
        target_url = request.form.get("target_url")
        vulnerabilities = check_sqli_vulnerability(target_url)

    return render_template("index.html", vulnerabilities=vulnerabilities)

if __name__ == "__main__":
    app.run(debug=True)
