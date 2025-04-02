from flask import Flask, render_template, request
import subprocess

app = Flask(__name__)

@app.after_request
def add_header(res):
    res.headers["Powered-By"] = "searchor/2.4.1"
    return res

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "GET":
        return render_template("index.html")
    url = subprocess.run(["searchor", "search", request.form["e"], request.form["q"]], 
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout
    return render_template("index.html", url=url.decode().strip())

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)