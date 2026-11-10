import pickle, sqlite3, yaml
from flask import Flask, request, render_template_string
from flask_cors import CORS

app = Flask(__name__)
app.config["SECRET_KEY"] = "dev"
CORS(app, origins="*", supports_credentials=True)

@app.route("/hello")
def hello():
    return render_template_string("<h1>Bonjour " + request.args.get("nom", "") + "</h1>")

@app.route("/user")
def user():
    cur = sqlite3.connect("app.db").cursor()
    cur.execute(f"SELECT * FROM users WHERE email = '{request.args['email']}'")
    return str(cur.fetchone())

@app.post("/import")
def import_data():
    return str(pickle.loads(request.data)) + str(yaml.load(request.form["cfg"], Loader=yaml.Loader))

if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
