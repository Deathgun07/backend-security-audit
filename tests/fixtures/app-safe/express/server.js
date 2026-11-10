const express = require("express");
const { requireAuth } = require("./auth");
const app = express();

app.post("/login", async (req, res) => res.json({ ok: true }));
app.put("/me", requireAuth, async (req, res) => res.json(req.user));
app.delete("/orders/:id", requireAuth, async (req, res) => res.sendStatus(204));
