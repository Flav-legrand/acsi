# Guide pas-à-pas : brancher une application Laravel 11 sur l'IAM-Local

Ce guide décrit comment ajouter une application Laravel à l'IAM ACSI. Il prend comme exemples les deux premières applications intégrées :

| Application | Code IAM | URL | Client OIDC | Permissions |
|---|---|---|---|---|
| Gestion des Partenaires | `partenaires` | `http://localhost:8001` | `iam-laravel-partenaires` | 25 (5 modules × 5 actions) |
| Gestion des Stages et Emplois | `stages-emplois` | `http://localhost:8002` | `iam-laravel-stages-emplois` | 30 (6 modules × 5 actions) |

---

## 1. Vue d'ensemble

```
 Navigateur            Application Laravel                    IAM-Local
 ──────────            ───────────────────                    ─────────
  /login  ───────────► IamAuthController::loginOidc
                        (state, nonce, PKCE verifier en session)
          ◄─────────── redirection ─────────────────────────► oauth.php
                                                                login.php → mfa.php
                                                                consentement
          ◄──────────────────────────── /callback?code&state ─┘
                       IamAuthController::callback
                        POST api/oauth/token.php ────────────► code + verifier + secret
                        ◄──────────── id_token, access_token (JWT RS256), refresh_token
                        vérification JWT via api/oauth/jwks.php (clé PUBLIQUE)
                        session Laravel : identité, rôles, permissions
  pages   ───────────► iam.auth (revérifie le JWT, le renouvelle si expiré)
                        iam.permission:<code> (200 ou 403)
```

Le **SSO maison** reste disponible en option (`/login/sso`) : `sso/authorize.php` renvoie un jeton à usage unique sur `/callback/sso`, que Laravel valide **serveur à serveur** par `api/sso/validate.php`. Les deux voies ouvrent la même session Laravel.

### Où sont les droits ?

- Ils sont **déclarés dans l'IAM uniquement** : permissions (`table permissions`), rôles locaux (`roles.application_id`), matrice (`role_permissions`), attribution aux comptes (`user_roles.application_id`).
- Laravel les **reçoit** à la connexion (claims `roles` et `permissions` de l'access token OIDC, ou réponse de `validate.php`) et ne les stocke pas en base.
- Une modification faite dans l'IAM s'applique à la prochaine connexion, ou au prochain renouvellement de jeton (toutes les heures au plus).

### Codes de permission

`permissions.code` est **unique sur toute la plateforme**. Les codes sont donc préfixés par le code de l'application : `<application>.<module>.<action>`, par exemple `partenaires.conventions.edit` ou `stages-emplois.offres-emploi.export`.

---

## 2. Ce qui a été ajouté ou modifié dans l'IAM

| Fichier | Nature |
|---|---|
| `sql/seed-app-partenaires.sql` | **Nouveau.** Application, client OIDC, 25 permissions, 3 rôles, matrice, 3 comptes de test. |
| `sql/seed-app-stages-emplois.sql` | **Nouveau.** Idem, 30 permissions. |
| `includes/oauth.php` | **Modifié (ajout).** Les jetons OIDC portent désormais une claim `permissions` (scope `roles`), calculée comme `api/sso/validate.php`. Nouvelle fonction `iam_oauth_user_permissions()`. Les clients existants reçoivent une claim de plus, rien d'autre ne change. |
| `.well-known/openid-configuration.php` et `api/oauth/.well-known/openid-configuration.php` | **Modifiés.** Annoncent les scopes `roles`, `offline_access`, les claims `roles`, `permissions` et le point de déconnexion `end_session_endpoint`. |
| `includes/platforms/LaravelPlatform.php` | **Modifié.** Valeurs par défaut de l'assistant OIDC alignées sur le squelette : `/callback`, `/logged-out`, `offline_access`, `firebase/php-jwt`. |
| `tools/generateur-app/piles/laravel/` | **Nouveau.** 25 gabarits de la pile Laravel (`env.example.gabarit` est rendu en `.env.example`). |
| `tools/generateur-app/generer.py` | **Modifié.** Pile `laravel` (sur demande uniquement), contrôle de cohérence étendu aux fichiers `.php` et aux codes contenant un tiret, correction de la matrice Markdown (toutes les cases étaient cochées). |
| `tools/generateur-app/lire_iam.py` | **Modifié.** Lit le client OIDC, la couleur et les comptes de test. Corrige la requête de la matrice (`IN (…)` sans parenthèses : erreur SQL dès qu'une application avait des rôles). La racine de l'IAM est déduite de l'emplacement du script. |
| `tools/generateur-app/sortie/partenaires/laravel/` et `sortie/stages-emplois/laravel/` | **Nouveaux.** Les deux squelettes générés. |
| `tools/tests/test_integration_laravel.php` | **Nouveau.** Test de bout en bout lancé depuis l'IAM, MFA comprise. |

---

## 3. Étape 1 — Déclarer l'application dans l'IAM

### 3.1 Importer le seed

**phpMyAdmin** : base `iam_local` › onglet *Importer* › `sql/seed-app-partenaires.sql` › *Exécuter*. Recommencer avec `sql/seed-app-stages-emplois.sql`.

**Ou en ligne de commande** (console WAMP) :

```bat
cd C:\wamp64\www\IAM-Local
C:\wamp64\bin\mysql\mysql<version>\bin\mysql.exe -u root iam_local < sql\seed-app-partenaires.sql
C:\wamp64\bin\mysql\mysql<version>\bin\mysql.exe -u root iam_local < sql\seed-app-stages-emplois.sql
```

La dernière requête de chaque script affiche le nombre de droits par rôle :

| Rôle | partenaires | stages-emplois |
|---|---|---|
| admin | 25 | 30 |
| gestionnaire | 20 | 24 |
| utilisateur | 5 | 6 |

Si un rôle affiche 0, c'est que l'IAM n'a pas d'administrateur actif sur `iam-admin` : relancer `install.php`.

### 3.2 Ce que fait le seed

| Section | Contenu | Au second passage |
|---|---|---|
| 1. `applications` | code, nom, URL, couleur, icône, `sso_prompt = 0` | met à jour nom, description, client_id, redirect_uri, scopes. **Conserve** URL, état actif, couleur, icône. |
| 2. `oauth_clients` | confidentiel, **PKCE obligatoire**, `redirect_uris = [<url>/callback]`, `post_logout_uris = [<url>/logged-out]`, scopes `openid profile email roles offline_access`, grants `authorization_code refresh_token` | rétablit la configuration de référence. **Conserve le secret** (une rotation faite dans l'admin n'est pas écrasée) et l'état actif. |
| 3. `permissions` | `<app>.<module>.<action>` pour view, create, edit, delete, export | met à jour les libellés. |
| 4. `roles` | `admin`, `gestionnaire`, `utilisateur`, locaux (`application_id`), `is_system = 0` | met à jour les libellés. |
| 5. `role_permissions` | matrice ci-dessous | **reconstruite** : un droit retiré du script disparaît. Les droits ajoutés à la main sur ces trois rôles sont donc perdus. |
| 6. `users`, `password_history`, `user_roles` | 3 comptes `<rôle>.<app>@acsi.local`, mot de passe = celui de l'administrateur IAM (comme `seed-demo.sql`), `must_change_password = 0` | **ne modifie pas** un compte existant. |

Tout est résolu par **code**, jamais par identifiant numérique. Le script peut être rejoué autant de fois que nécessaire.

### 3.3 Matrice rôles × permissions (identique pour chaque module)

| Rôle | view | create | edit | delete | export |
|---|---|---|---|---|---|
| admin | ✔ | ✔ | ✔ | ✔ | ✔ (+ joker `*`) |
| gestionnaire | ✔ | ✔ | ✔ | — | ✔ |
| utilisateur | ✔ | — | — | — | — |

Le rôle `admin` **de l'application** a `is_system = 0` : il ne donne **aucun** droit sur la console IAM.

> **À valider.** Pour modifier la matrice : soit dans l'admin (Rôles), soit dans la section 5 du seed (clause `WHERE` de l'`INSERT INTO role_permissions`, qui liste les actions accordées à chaque rôle), puis rejouer le seed. Pensez ensuite à régénérer le squelette (§ 4) pour que `iam:test-login` compare avec la nouvelle matrice.

### 3.4 Secret client

L'IAM ne stocke que le haché bcrypt du secret. Le secret **de développement** est écrit en tête de chaque seed. Il ne vaut qu'en local. Avant toute autre utilisation : Administration › *Applications OAuth / OIDC* › l'application › **Régénérer le secret** (affiché une seule fois), puis le reporter dans le `.env` Laravel.

---

## 4. Étape 2 — Générer le squelette Laravel

Les deux squelettes sont **déjà générés** dans `tools/generateur-app/sortie/`. Pour les régénérer (après un ajout de permission, par exemple) :

```bat
cd C:\wamp64\www\IAM-Local\tools\generateur-app
pip install pymysql
python generer.py --app partenaires --piles laravel --sortie sortie\partenaires --force
python generer.py --app stages-emplois --piles laravel --sortie sortie\stages-emplois --force
```

Le générateur lit la base : les codes de permission, la matrice et les comptes de test sont **exacts par construction**. Il signale tout code cité dans le squelette mais absent de l'IAM (code de sortie 3).

Contenu du squelette, fichier par fichier : voir le `README.md` à la racine de chaque squelette.

---

## 5. Étape 3 — Créer le projet Laravel

Exemple pour `partenaires` (même chose pour `stages-emplois` avec le port 8002) :

```bat
cd C:\wamp64\www
composer create-project laravel/laravel:^11.0 partenaires
cd partenaires
composer require firebase/php-jwt:^6.10

xcopy /E /Y /I C:\wamp64\www\IAM-Local\tools\generateur-app\sortie\partenaires\laravel .

copy env.example .env
php artisan key:generate
```

> Le squelette livré contient `env.example` **sans point** (l'outil de copie vers votre poste refuse les fichiers `.env*`). Un squelette régénéré par `generer.py` contient `.env.example` : utiliser alors `copy .env.example .env`. Attention : le `.env.example` d'origine de Laravel ne contient pas le bloc IAM.

Dans `.env`, renseigner `IAM_OIDC_CLIENT_SECRET` (§ 3.4). Les autres valeurs sont déjà correctes pour WAMP.

```bat
php artisan migrate
php artisan db:seed --class=IamTestUsersSeeder
php artisan iam:check
php artisan serve --port=8001
```

`iam:check` doit afficher **« Configuration IAM correcte »** :

```
== Configuration
  ✔ base_url                   http://localhost/IAM-Local
  ✔ app_code                   partenaires
  ✔ client_id                  iam-laravel-partenaires
  ✔ client_secret              ••••••••f025
  ✔ redirect_uri               http://localhost:8001/callback
  ✔ post_logout_redirect_uri   http://localhost:8001/logged-out
  ✔ Cookie de session dédié (partenaires_session) : …
== IAM
  ✔ Découverte OIDC : issuer = http://localhost/IAM-Local
  ✔ JWKS : 1 clé(s) publique(s)
  ✔ Client OIDC reconnu et secret accepté
  ✔ SSO maison : validate.php répond (jeton factice refusé, HTTP 401)
== Laravel
  ✔ Colonne users.iam_sub (php artisan migrate)
```

> **Deux applications Laravel sur `localhost`** : chaque `.env` définit son propre `SESSION_COOKIE` (`partenaires_session`, `stages_emplois_session`). Les navigateurs ne distinguent pas les ports : avec le cookie par défaut `laravel_session`, se connecter sur l'une déconnecterait l'autre.

---

## 6. Étape 4 — Tester

### 6.1 Dans le navigateur

1. Ouvrir `http://localhost:8001` : redirection vers la page de connexion IAM.
2. Se connecter avec `gestionnaire.partenaires@acsi.local` et le mot de passe des comptes de démonstration.
3. Saisir le code MFA (affiché sur la page si le SMTP n'est pas configuré).
4. Cliquer sur **Autoriser** (consentement OIDC).
5. L'accueil affiche les modules. Dans *Contacts* : boutons *Modifier* présents, *Supprimer* absent. L'URL d'un écran interdit renvoie une page 403.

### 6.2 Depuis Laravel : `php artisan iam:test-login`

```bat
php artisan iam:test-login utilisateur.partenaires@acsi.local
php artisan iam:test-login gestionnaire.partenaires@acsi.local --mode=sso
```

La commande joue le rôle du navigateur, compare les rôles et permissions reçus avec la matrice, vérifie chaque écran (200 si permis, 403 sinon), puis se déconnecte :

```
  ✔ Rôles conformes : utilisateur
  ✔ Permissions conformes à la matrice (5 attendues)
+-------------+-------+--------+-------+--------+
| module      | view  | create | edit  | export |
| contacts    | ✔ 200 | ✔ 403  | ✔ 403 | ✔ 403  |
…
RÉSULTAT : tout est conforme.
```

### 6.3 Depuis l'IAM : test automatique complet

```bat
cd C:\wamp64\www\IAM-Local
php tools\tests\test_integration_laravel.php --app=partenaires --password=<mot de passe démo>
php tools\tests\test_integration_laravel.php --app=stages-emplois --password=<mot de passe démo>
```

Le script vérifie la configuration en base, puis connecte **chaque compte de test par les deux voies**. Il génère le code MFA directement en base, sans intervention, et compare `/iam/me` aux droits calculés par l'IAM lui-même. Il est réservé à la ligne de commande (404 s'il est appelé par le web).

### 6.4 Résultats obtenus avant livraison

Les tests ont tourné sur une copie de l'IAM (schéma, seeds métier, migration des rôles locaux, puis les deux nouveaux seeds), avec deux vrais projets Laravel 11.36 :

| Scénario | Résultat |
|---|---|
| 2 applications × 3 rôles × 2 voies (OIDC, SSO maison) | 12/12 conformes : rôles, permissions, 200/403 écran par écran, déconnexion |
| Compte `partenaires` sur `stages-emplois` | refusé : 403 Laravel (OIDC), 403 IAM (SSO maison) |
| Access token expiré | renouvelé automatiquement par le refresh token |
| API Bearer : jeton valide / signature falsifiée / jeton d'une autre application | 200 / 401 / 401 (`aud`) |
| Gestionnaire qui force `DELETE /contacts/1` | 403 |
| Mauvais secret client | `iam:check` le signale |
| Seeds rejoués deux fois | aucune erreur, aucun doublon ; applications existantes intactes |
| Pages IAM testées (portail, admin : accueil, applications, OIDC, rôles, utilisateurs, audit, sessions) | toutes en 200, sans erreur PHP ; les deux applications y apparaissent |

---

## 7. Ajouter une troisième application Laravel

1. **Copier un seed** : `sql/seed-app-partenaires.sql` → `sql/seed-app-<code>.sql`. Remplacer le code, le nom, l'URL et le port, et la liste des permissions (section 3). Générer un nouveau secret et son haché :
   ```bat
   php -r "$s='dev-<code>-'.bin2hex(random_bytes(16)); echo $s, PHP_EOL, password_hash($s, PASSWORD_BCRYPT), PHP_EOL;"
   ```
   Mettre le haché dans l'`INSERT INTO oauth_clients` et le secret en clair dans l'en-tête.
   *Ou* créer l'application dans Administration › *Applications OAuth / OIDC* › **Nouvelle application** (plateforme **Laravel**), puis déclarer permissions et rôles dans *Rôles*.
2. Importer le seed (§ 3.1).
3. Générer : `python generer.py --app <code> --piles laravel --sortie sortie\<code>`.
4. Créer le projet (§ 5), avec un port libre et un `SESSION_COOKIE` propre.
5. Tester (§ 6).

---

## 8. Dépannage

| Symptôme | Où regarder | Correction |
|---|---|---|
| Page IAM « redirect_uri invalide pour ce client » | `oauth_clients.redirect_uris` | doit être **exactement** `IAM_OIDC_REDIRECT_URI` (port compris) |
| « Un code_challenge PKCE S256 valide est obligatoire » | — | passer par `/login/oidc` (le squelette envoie toujours PKCE) |
| « Échange de jeton refusé … invalid_client » | `php artisan iam:check` | mauvais `IAM_OIDC_CLIENT_SECRET` (§ 3.4) |
| « Émetteur inattendu » | `config/config.php` de l'IAM | `IAM_BASE_URL` Laravel ≠ `IAM_BASE_URL` IAM ; sinon renseigner `IAM_OIDC_ISSUER` |
| 403 « aucun rôle sur cette application » | Administration › Utilisateurs | attribuer un rôle **sur cette application** |
| Les deux applications se déconnectent mutuellement | `.env` | `SESSION_COOKIE` différent dans chaque application |
| Droits modifiés dans l'IAM non visibles | — | se reconnecter (ou attendre le renouvellement horaire du jeton) |
| Erreurs côté Laravel | `storage/logs/laravel.log` (lignes `[IAM]`) | |
| Erreurs côté IAM | Administration › *Journal d'audit* (`oauth_consent`, `oauth_token`, `sso_issue`, `sso_login`) ; log Apache/PHP de WAMP | |

---

## 9. Points de vigilance relevés dans l'IAM (non modifiés)

Ces comportements existaient avant ce chantier. Le squelette Laravel s'en protège, mais ils concernent toutes les applications :

1. **`oauth.php` délivre un code à tout utilisateur connecté**, qu'il ait ou non un rôle sur l'application. `sso/authorize.php`, lui, vérifie l'accès. Le squelette Laravel refuse un compte sans rôle (403), mais une autre application OIDC pourrait ne pas le faire.
2. **Le renouvellement (`grant_type=refresh_token`) ne vérifie pas le secret** d'un client confidentiel : seul le refresh token est contrôlé.
3. **Le consentement OIDC est redemandé à chaque connexion** : il n'est pas mémorisé.
4. **Les administrateurs IAM ne passent pas par la MFA** (`login.php` et `oauth.php`).
5. **`install.php` écrit un `config/config.php` sans `MFA_FORCE_ALL`** (ni les constantes `OAUTH_GOOGLE_*` et `OAUTH_MICROSOFT_*`) : sur une installation neuve, la première connexion d'un compte provoque une erreur fatale (`Undefined constant "MFA_FORCE_ALL"`). La configuration actuelle les contient, car elles ont été ajoutées à la main.
6. **`generer.py` propose par défaut les piles `react` et `express`**, dont les gabarits sont absents de `piles/` (seul `django/iam.py.gabarit` existe, et `piles/commun/` est absent).

Les points 5 et 6 relèvent du chantier 3 (nettoyage et configuration). Les points 1 à 4 demandent une décision de votre part.
