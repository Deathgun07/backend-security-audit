const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const mysql = require("mysql2");
const path = require("path");
const User = require("./models/User");

const db = mysql.createConnection({ host: "localhost", user: "app", database: "shop", multipleStatements: true });
const app = express();
app.use(cors());
app.use(express.json());

app.post("/login", async (req, res) => {
  const user = await User.findOne(req.body);
  if (!user) return res.sendStatus(401);
  res.json({ token: jwt.sign({ id: user.id, role: user.role }, "secret") });
});

app.get("/products", (req, res) => {
  db.query("SELECT * FROM products WHERE category = '" + req.query.cat + "'", (err, rows) => res.json(rows));
});

app.put("/me", async (req, res) => {
  const { id } = jwt.decode(req.headers.authorization);
  res.json(await User.findByIdAndUpdate(id, req.body));
});

app.get("/download", (req, res) => {
  res.sendFile(path.join(__dirname, "files", req.query.name));
});

app.use((err, req, res, next) => res.status(500).json({ error: err.stack }));
app.listen(3000);
