# Audit de sécurité backend — {{NOM_PROJET}}

| | |
|---|---|
| **Date** | {{AAAA-MM-JJ}} |
| **Commit audité** | `{{HASH_COURT}}` ({{BRANCHE}}) |
| **Stacks détectés** | {{STACKS}} |
| **Périmètre** | Code local du dépôt{{+ base Postgres locale / projet Supabase de l'utilisateur, si scan_rls exécuté}} |
| **Hors périmètre** | {{ex. : infrastructure, configuration du dashboard Supabase non exportée, tests dynamiques}} |

> Analyse statique en lecture seule : aucun fichier du projet n'a été modifié. Les correctifs sont proposés sous forme de diff.

## Résumé

**Score : {{SCORE}}/100** — {{une phrase de verdict}}

| Sévérité | Confirmées | À vérifier |
|---|---|---|
| 🔴 Critique | {{n}} | {{n}} |
| 🟠 Haute | {{n}} | {{n}} |
| 🟡 Moyenne | {{n}} | {{n}} |
| 🔵 Basse | {{n}} | {{n}} |
| ⚪ Info | {{n}} | {{n}} |

<!-- Score = 100 − (25×Critique + 10×Haute + 4×Moyenne + 1×Basse) pour les confirmées,
     moitié de ces poids pour les « à vérifier », Info = 0. Plancher 0. -->

## Tableau récapitulatif

| ID | Sévérité | Titre | OWASP | Emplacement | Statut |
|---|---|---|---|---|---|
| SEC-01 | Critique | {{titre court}} | A01 | `{{fichier}}:{{ligne}}` | Confirmé |

## Détail des failles

### SEC-01 — {{Titre}}

- **Sévérité** : {{Critique / Haute / Moyenne / Basse / Info}}
- **Catégorie OWASP** : {{A0x — nom}}
- **Emplacement** : `{{fichier}}:{{ligne}}`
- **Statut** : {{Confirmé | À vérifier manuellement — ce qu'il faut vérifier et comment}}

**Preuve**
```{{langage}}
{{extrait exact, 3 à 10 lignes, numéros de ligne en commentaire ; secrets masqués : sk_live_51H…****}}
```

**Impact concret**
{{Qui peut faire quoi, depuis où, avec quelles conséquences. Ex. : « Tout visiteur non connecté peut lire les 2 000 factures via GET /rest/v1/invoices avec la clé anon publique. »}}

**Correctif proposé**
```diff
--- a/{{fichier}}
+++ b/{{fichier}}
@@ {{ligne}} @@
-{{ligne vulnérable}}
+{{ligne corrigée}}
```
{{Actions hors code si nécessaire : rotation de clé, migration à appliquer, réglage dashboard.}}

---

## Points positifs

- {{Bonne pratique constatée, avec fichier à l'appui. Ex. : « Requêtes PocketBase paramétrées via pb.filter() (lib/data.ts:42). »}}

## Priorités de correction

1. **SEC-0x** — {{action concrète}} ({{effort estimé : 5 min / 1 h / 1 j}})
2. …
3. …
4. …
5. …

## Annexes

### Commandes exécutées
```
{{detect_stack.sh, find_secrets.sh, grep_patterns.sh, audit de dépendances, scan_rls.sql}}
```

### Pistes écartées (faux positifs)
| Emplacement | Motif | Raison |
|---|---|---|
| `{{fichier}}:{{ligne}}` | {{pattern}} | {{ex. : clé anon publique, fichier de test, valeur d'exemple}} |

### Non vérifié
- {{Ce qui n'a pas pu être contrôlé et pourquoi : outil absent, base non accessible, config hors dépôt.}}
