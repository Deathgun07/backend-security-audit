# Checklist Firebase

Sources : `firestore.rules`, `storage.rules`, `database.rules.json` (Realtime Database), `firebase.json`, `functions/` (Cloud Functions), code client (`initializeApp`), fichiers de compte de service.
Rappel : la config web (`apiKey: "AIza…"`, `projectId`) est **publique par conception** (Info). La seule barrière côté client, ce sont les **Security Rules**. Une règle non déployée dans le dépôt peut différer de la prod : vérifier aussi `firebase deploy --only firestore:rules` ou la console (→ « à vérifier »).

## FB1. Règles ouvertes (`if true`, sans condition) — Critique (A01)
```js
// ❌ firestore.rules
match /{document=**} { allow read, write: if true; }
match /users/{id} { allow read, write; }            // pas de condition = autorisé
// ✅
match /users/{uid} {
  allow read: if request.auth != null && request.auth.uid == uid;
  allow write: if request.auth != null && request.auth.uid == uid;
}
```
- `match /{document=**}` avec une règle permissive écrase tout le reste (les règles s'additionnent : une seule autorisation suffit).

## FB2. Règles « mode test » expirées ou à date — Haute (A01)
```js
// ❌ généré par la console
allow read, write: if request.time < timestamp.date(2026, 12, 31);
```
Public jusqu'à la date. Remplacer par des règles basées sur `request.auth`.

## FB3. `request.auth != null` seul — Haute (A01)
« Connecté » ≠ « propriétaire ». Avec l'inscription ouverte (email/anonyme), c'est quasi public.
```js
// ❌
match /orders/{id} { allow read, write: if request.auth != null; }
// ✅
match /orders/{id} {
  allow read: if request.auth != null && resource.data.userId == request.auth.uid;
  allow create: if request.auth != null && request.resource.data.userId == request.auth.uid;
  allow update: if request.auth != null && resource.data.userId == request.auth.uid
                && request.resource.data.userId == resource.data.userId;
}
```
- L'auth **anonyme** activée rend `request.auth != null` vrai pour tout visiteur.

## FB4. Champs de privilège modifiables — Critique (A01)
Un utilisateur qui peut écrire son document `users/{uid}` peut se donner `role: "admin"`, `credits`, `premium`.
```js
// ✅
allow update: if request.auth.uid == uid
  && !request.resource.data.diff(resource.data).affectedKeys().hasAny(['role', 'credits', 'premium']);
allow create: if request.auth.uid == uid
  && request.resource.data.keys().hasOnly(['name', 'avatar', 'createdAt']);
```
- Rôles : préférer les **custom claims** (`request.auth.token.admin == true`), posés uniquement via l'Admin SDK.

## FB5. Validation des données absente — Moyenne (A04)
Pas de contrôle de type/taille (`request.resource.data.text is string && request.resource.data.text.size() < 2000`) → stockage de gros documents, contenus arbitraires.

## FB6. Realtime Database ouverte — Critique (A01)
```json
// ❌ database.rules.json
{ "rules": { ".read": true, ".write": true } }
// ✅
{ "rules": { "users": { "$uid": {
  ".read": "auth != null && auth.uid === $uid",
  ".write": "auth != null && auth.uid === $uid" } } } }
```
- `".read": "auth != null"` à la racine = toute la base lisible par tout inscrit (Haute).

## FB7. Storage rules — Haute (A01)
```js
// ❌ storage.rules
match /{allPaths=**} { allow read, write: if request.auth != null; }
// ✅
match /users/{uid}/{file} {
  allow read: if request.auth.uid == uid;
  allow write: if request.auth.uid == uid
    && request.resource.size < 5 * 1024 * 1024
    && request.resource.contentType.matches('image/.*');
}
```

## FB8. Cloud Functions sans contrôle — Haute à Critique (A01)
- `onRequest` est un endpoint HTTP public : vérifier le jeton (`admin.auth().verifyIdToken(req.headers.authorization)`).
- `onCall` : vérifier `request.auth` (v2) / `context.auth` (v1) **et** l'appartenance des IDs reçus.
- L'Admin SDK **contourne toutes les rules** : chaque function fait elle-même l'autorisation.
```ts
// ❌
export const deleteOrder = onCall(async (req) => { await db.doc(`orders/${req.data.id}`).delete(); });
// ✅
export const deleteOrder = onCall(async (req) => {
  if (!req.auth) throw new HttpsError("unauthenticated", "Connexion requise");
  const ref = db.doc(`orders/${req.data.id}`);
  const snap = await ref.get();
  if (snap.get("userId") !== req.auth.uid) throw new HttpsError("permission-denied", "Interdit");
  await ref.delete();
});
```
- CORS `cors: true` / `origin: "*"` sur des functions qui lisent un cookie de session : Moyenne.

## FB9. Compte de service commité — Critique (A02)
Fichier JSON contenant `"type": "service_account"` et `"private_key"` → accès admin total au projet. Retirer, **révoquer la clé** dans IAM, utiliser les identifiants par défaut de l'environnement.

## FB10. App Check et quotas — Basse (A04)
Sans App Check, n'importe quel script peut appeler Firestore/Functions avec la config publique : faciliter l'abus (coûts, spam). Signaler en Basse si des fonctions coûteuses (IA, SMS, email) sont exposées → Moyenne.

## FB11. Auth — Moyenne (A07)
Inscription email/mot de passe sans vérification d'email utilisée comme preuve d'identité (`request.auth.token.email_verified` non vérifié dans les rules qui se basent sur l'email) ; domaines autorisés trop larges.
