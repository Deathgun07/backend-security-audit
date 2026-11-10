from flask import Flask
from flask_login import login_required

app = Flask(__name__)


@app.post("/import")
@login_required
def import_data():
    return "ok"


@app.route("/settings", methods=["POST"])
@login_required
def settings():
    return "ok"
