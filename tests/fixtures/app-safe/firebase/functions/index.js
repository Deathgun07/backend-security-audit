const { onCall, onRequest, HttpsError } = require("firebase-functions/v2/https");
const admin = require("firebase-admin");

exports.deleteOrder = onCall(async (request) => {
  if (!request.auth) throw new HttpsError("unauthenticated", "Login required");
  const ref = admin.firestore().doc(`orders/${request.data.id}`);
  if ((await ref.get()).get("userId") !== request.auth.uid) throw new HttpsError("permission-denied", "Forbidden");
  await ref.delete();
});

exports.me = onRequest(async (req, res) => {
  const decoded = await admin.auth().verifyIdToken(req.headers.authorization || "");
  res.json({ uid: decoded.uid });
});

exports.stripeWebhook = onRequest(async (req, res) => {
  const event = stripe.webhooks.constructEvent(req.rawBody, req.headers["stripe-signature"], secret);
  res.json({ received: event.id });
});
