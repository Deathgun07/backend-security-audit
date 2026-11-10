const { onCall, onRequest } = require("firebase-functions/v2/https");
const admin = require("firebase-admin");
admin.initializeApp();

exports.deleteOrder = onCall(async (req) => {
  await admin.firestore().doc(`orders/${req.data.id}`).delete();
});

exports.setRole = onRequest({ cors: true }, async (req, res) => {
  await admin.auth().setCustomUserClaims(req.body.uid, { admin: true });
  res.send("ok");
});
