# Gestion des Stages et Emplois — intégration Laravel 11 avec l'IAM-Local

Squelette généré le 2026-10-13 par `tools/generateur-app` (pile `laravel`), à partir de la déclaration de l'application **`stages-emplois`** dans la base de l'IAM.

| Élément | Valeur |
|---|---|
| URL de l'application | `http://localhost:8002` |
| IAM | `http://localhost/IAM-Local` |
| Client OIDC | `iam-laravel-stages-emplois` (confidentiel, PKCE S256 obligatoire) |
| Redirect URI enregistrée | `http://localhost:8002/callback` |
| Permissions | 30 |
| Rôles locaux | 3 |

Ce dossier **n'est pas** un projet Laravel complet : il se copie **par-dessus** un projet Laravel 11 neuf. Les fichiers portant le même nom qu'un fichier du projet neuf (`bootstrap/app.php`, `bootstrap/providers.php`, `config/services.php`, `routes/web.php`, `.env.example`) le **remplacent** : ils reprennent le contenu d'origine de Laravel 11, avec l'IAM en plus.

---

## 1. Installation pas à pas

Prérequis : PHP 8.2+, Composer, et l'application déclarée dans l'IAM (`sql/seed-app-stages-emplois.sql` importé côté IAM).

```bash
# 1. Projet Laravel 11 neuf
composer create-project laravel/laravel:^11.0 stages-emplois
cd stages-emplois

# 2. Bibliothèque de vérification des JWT (RS256 / JWKS)
composer require firebase/php-jwt:^6.10

# 3. Copier ce squelette PAR-DESSUS le projet (fichiers cachés compris)
#    Windows :  xcopy /E /Y /I <chemin>\sortie\stages-emplois\laravel .
#    Linux   :  cp -r <chemin>/sortie/stages-emplois/laravel/. .

# 4. Configuration
copy .env.example .env          # Linux : cp .env.example .env
#    Si le squelette contient « env.example » (sans point : copie
#    transférée par un outil qui refuse les fichiers .env*), utiliser
#    copy env.example .env  — sinon on obtient le .env.example de
#    Laravel, sans le bloc IAM.
php artisan key:generate
#    puis renseigner IAM_OIDC_CLIENT_SECRET dans .env (voir § 3)

# 5. Base locale : colonne users.iam_sub, comptes de test locaux
php artisan migrate
php artisan db:seed --class=IamTestUsersSeeder

# 6. Vérifier la configuration, puis lancer
php artisan iam:check
php artisan serve --port=8002
```

Ouvrir `http://localhost:8002` : l'application redirige vers l'IAM, puis revient connectée.

---

## 2. Fichiers livrés

| Fichier | Rôle |
|---|---|
| `.env.example` (ou `env.example`) | `.env` Laravel 11 complet + bloc **IAM**. `SESSION_COOKIE` est propre à l'application : sinon deux applications Laravel sur `localhost` partagent le cookie `laravel_session` et se déconnectent l'une l'autre (les navigateurs ignorent le port). |
| `config/services.php` | Fichier Laravel d'origine + clé `iam` : URL de l'IAM, `client_id`, `client_secret` (lu du `.env`, jamais écrit en dur), URIs de retour, scopes, mode par défaut. |
| `bootstrap/app.php` | Fichier Laravel d'origine + alias de middlewares `iam.auth` et `iam.permission` ; les invités sont renvoyés vers `/login`. |
| `bootstrap/providers.php` | Enregistre `IamServiceProvider`. |
| `routes/web.php` | Routes d'authentification (`/login`, `/callback`, `/logout`…) et routes de démonstration de chaque module, protégées permission par permission. |
| `app/Iam/IamClient.php` | Dialogue avec l'IAM : PKCE, échange du code, rafraîchissement, **vérification des JWT par la clé publique (JWKS)**, appel serveur à serveur de `validate.php`, URL de déconnexion. |
| `app/Iam/IamUser.php` | Utilisateur IAM courant : identité, rôles, permissions, `can()`, accès à l'application. `IamUser::current()` partout. |
| `app/Iam/Permissions.php` | **Généré depuis la base de l'IAM** : une constante par permission, la liste des modules, la matrice rôles × permissions et les comptes de test (ces deux derniers servent uniquement aux tests). |
| `app/Iam/IamException.php` | Erreur de dialogue avec l'IAM. |
| `app/Http/Middleware/IamAuth.php` | Middleware `iam.auth` : session web (access token **revérifié à chaque requête**, renouvelé par refresh token) ou en-tête `Authorization: Bearer` pour les API. Refuse (403) un compte sans rôle sur l'application. |
| `app/Http/Middleware/IamPermission.php` | Middleware `iam.permission:<code>[,<code>…]` : 403 si aucune des permissions n'est accordée. |
| `app/Http/Controllers/IamAuthController.php` | Connexion OIDC, connexion SSO maison, callbacks, déconnexion, diagnostic `/iam/me` (environnement `local` uniquement). |
| `app/Http/Controllers/ModuleController.php` | Écrans de **démonstration** des modules (aucune logique métier) : à remplacer par vos contrôleurs en gardant les middlewares. |
| `app/Providers/IamServiceProvider.php` | Singleton `IamClient`, directives Blade `@iamcan` / `@iamrole`, `Gate::before` pour les codes de l'application, `$iamUser` dans toutes les vues, commandes artisan. |
| `app/Console/Commands/IamCheck.php` | `php artisan iam:check` : configuration, découverte OIDC, JWKS, **secret client accepté ?**, SSO maison, migration. |
| `app/Console/Commands/IamTestLogin.php` | `php artisan iam:test-login <email>` : connexion complète simulée (navigateur), comparaison rôles/permissions avec la matrice, contrôle 200/403 de chaque écran, déconnexion. |
| `database/migrations/…_add_iam_sub_to_users_table.php` | Colonne `users.iam_sub` (identifiant IAM). Les droits ne sont **pas** stockés localement. |
| `database/seeders/IamTestUsersSeeder.php` | Crée les comptes de test **locaux** (miroirs des comptes IAM). Ils ne servent pas à se connecter : l'authentification passe toujours par l'IAM. |
| `resources/views/iam/*.blade.php` | Gabarit, accueil, écran de module, 403, erreur de connexion, page « déconnecté ». |

---

## 3. Secret client

L'IAM ne stocke que le **haché** du secret (bcrypt) : impossible de le relire en base.

- **En local** : le secret de développement figure en tête de `sql/seed-app-stages-emplois.sql` côté IAM. Le copier dans `IAM_OIDC_CLIENT_SECRET`.
- **Ailleurs** : IAM › Administration › *Applications OAuth / OIDC* › `Gestion des Stages et Emplois` › **Régénérer le secret**. Il est affiché une seule fois. Rejouer le seed ensuite **ne l'écrase pas**.

`php artisan iam:check` indique immédiatement si le secret est refusé.

---

## 4. Les deux voies de connexion

| | OIDC + PKCE (défaut) | SSO maison (option) |
|---|---|---|
| Lancement | `/login` ou `/login/oidc` | `/login/sso` (ou `IAM_AUTH_MODE=sso`) |
| Côté IAM | `oauth.php` → consentement → `api/oauth/token.php` | `sso/authorize.php` → `api/sso/validate.php` |
| Retour | `/callback?code=…&state=…` | `/callback/sso?sso_token=…` |
| Preuve d'identité | `id_token` et `access_token` **RS256 vérifiés avec la clé publique** (signature, `iss`, `aud`, `exp`, `nonce`) | réponse de `validate.php`, obtenue **serveur à serveur** avec un jeton à usage unique (60 s). Le JWT HS256 n'est pas vérifié (il faudrait partager le secret de l'IAM). |
| Droits | claims `roles` et `permissions` de l'access token | champs `roles` et `permissions` de la réponse |
| Durée | access token 1 h, renouvelé par refresh token (rotation) | `IAM_SSO_SESSION_TTL` (8 h par défaut) |
| API (Bearer) | oui | non |

Les deux voies produisent **la même session** : `IamUser::current()`, les middlewares et `@iamcan` ne font pas la différence.

---

## 5. Protéger routes et vues

```php
use App\Iam\Permissions;

// Route : bloquer
Route::get('/contrats', [ContratController::class, 'index'])
    ->middleware(['iam.auth', 'iam.permission:'.Permissions::code('conventions', 'view')]);

// Contrôleur
abort_unless(IamUser::current()?->can(Permissions::code('conventions', 'edit')), 403);

// Gate Laravel : les codes de l'application passent par l'IAM
$this->authorize(Permissions::code('conventions', 'delete'));
```

```blade
{{-- Vue : cacher --}}
@iamcan('stages-emplois.conventions.create')
    <a href="{{ route('conventions.create') }}">Nouvelle convention</a>
@endiamcan

@iamrole('admin') … @endiamrole
```

**API (jeton Bearer)** : un client qui détient un access token de l'IAM émis **pour cette application** l'envoie dans `Authorization: Bearer …`. Le jeton est vérifié à chaque appel (signature, `exp`, `iss`, `aud`) ; un jeton émis pour une autre application est refusé (401).

```bash
php artisan install:api      # crée routes/api.php (groupe « api », sans session)
```

```php
// routes/api.php
Route::middleware(['iam.auth', 'iam.permission:stages-emplois.rapports.export'])
    ->get('/rapports/export', [RapportApiController::class, 'export']);
```

Règles d'accès (`IamUser::can`) :

- `*` (joker) : tout. L'IAM l'accorde au rôle `admin` de l'application et aux administrateurs de la plateforme IAM ;
- sinon la permission doit figurer dans la liste reçue ;
- **lecture seule par défaut** : si l'IAM n'a transmis **aucune** permission, seules les permissions `*.view` passent (`IAM_READONLY_FALLBACK=false` pour désactiver) ;
- un compte **sans aucun rôle** sur l'application est refusé (403), même s'il est connecté à l'IAM.

---

## 6. Permissions et matrice déclarées dans l'IAM

- `stages-emplois.candidatures.create` — Créer une candidature (Ajouter une candidature)
- `stages-emplois.candidatures.delete` — Supprimer une candidature (Supprimer définitivement une candidature)
- `stages-emplois.candidatures.edit` — Modifier une candidature (Modifier une candidature existant(e))
- `stages-emplois.candidatures.export` — Exporter les candidatures (Exporter les candidatures (CSV, Excel, PDF))
- `stages-emplois.candidatures.view` — Voir les candidatures (Consulter les candidatures (lecture seule))
- `stages-emplois.conventions.create` — Créer une convention de stage (Ajouter une convention de stage)
- `stages-emplois.conventions.delete` — Supprimer une convention de stage (Supprimer définitivement une convention de stage)
- `stages-emplois.conventions.edit` — Modifier une convention de stage (Modifier une convention de stage existant(e))
- `stages-emplois.conventions.export` — Exporter les conventions de stage (Exporter les conventions de stage (CSV, Excel, PDF))
- `stages-emplois.conventions.view` — Voir les conventions de stage (Consulter les conventions de stage (lecture seule))
- `stages-emplois.employes.create` — Créer un employé (Ajouter un employé)
- `stages-emplois.employes.delete` — Supprimer un employé (Supprimer définitivement un employé)
- `stages-emplois.employes.edit` — Modifier un employé (Modifier un employé existant(e))
- `stages-emplois.employes.export` — Exporter les employés (Exporter les employés (CSV, Excel, PDF))
- `stages-emplois.employes.view` — Voir les employés (Consulter les employés (lecture seule))
- `stages-emplois.offres-emploi.create` — Créer une offre d'emploi (Ajouter une offre d'emploi)
- `stages-emplois.offres-emploi.delete` — Supprimer une offre d'emploi (Supprimer définitivement une offre d'emploi)
- `stages-emplois.offres-emploi.edit` — Modifier une offre d'emploi (Modifier une offre d'emploi existant(e))
- `stages-emplois.offres-emploi.export` — Exporter les offres d'emploi (Exporter les offres d'emploi (CSV, Excel, PDF))
- `stages-emplois.offres-emploi.view` — Voir les offres d'emploi (Consulter les offres d'emploi (lecture seule))
- `stages-emplois.rapports.create` — Créer un rapport (Ajouter un rapport)
- `stages-emplois.rapports.delete` — Supprimer un rapport (Supprimer définitivement un rapport)
- `stages-emplois.rapports.edit` — Modifier un rapport (Modifier un rapport existant(e))
- `stages-emplois.rapports.export` — Exporter les rapports (Exporter les rapports (CSV, Excel, PDF))
- `stages-emplois.rapports.view` — Voir les rapports (Consulter les rapports (lecture seule))
- `stages-emplois.stages.create` — Créer un stage (Ajouter un stage)
- `stages-emplois.stages.delete` — Supprimer un stage (Supprimer définitivement un stage)
- `stages-emplois.stages.edit` — Modifier un stage (Modifier un stage existant(e))
- `stages-emplois.stages.export` — Exporter les stages (Exporter les stages (CSV, Excel, PDF))
- `stages-emplois.stages.view` — Voir les stages (Consulter les stages (lecture seule))

| Module | `admin` | `gestionnaire` | `utilisateur` |
|---|---|---|---|
| Candidatures | create, delete, edit, export, view | create, edit, export, view | view |
| Conventions de stage | create, delete, edit, export, view | create, edit, export, view | view |
| Employés | create, delete, edit, export, view | create, edit, export, view | view |
| Offres d'emploi | create, delete, edit, export, view | create, edit, export, view | view |
| Rapports | create, delete, edit, export, view | create, edit, export, view | view |
| Stages | create, delete, edit, export, view | create, edit, export, view | view |

Règle complémentaire de l'IAM : le rôle `admin` reçoit aussi le joker `*`.

Pour modifier les droits : Administration IAM › **Rôles** (effet à la prochaine connexion ou au prochain renouvellement de jeton, sans toucher à Laravel). Pour ajouter une **permission**, la déclarer dans l'IAM puis régénérer `app/Iam/Permissions.php` :

```bash
cd C:\wamp64\www\IAM-Local\tools\generateur-app
python generer.py --app stages-emplois --piles laravel --sortie sortie\stages-emplois --force
```

---

## 7. Tester

```bash
php artisan iam:check

# Dans un second terminal : php artisan serve --port=8002
php artisan iam:test-login admin.stages-emplois@acsi.local
php artisan iam:test-login gestionnaire.stages-emplois@acsi.local
php artisan iam:test-login utilisateur.stages-emplois@acsi.local --mode=sso
```

Le mot de passe demandé est celui des comptes de démonstration de l'IAM. Le code MFA est lu sur la page lorsque le SMTP de l'IAM n'est pas configuré (mode démo) ; sinon la commande le demande (`--otp=123456` possible).

Test entièrement automatique, MFA comprise, depuis l'IAM : `php tools/tests/test_integration_laravel.php --app=stages-emplois --password=<mot de passe démo>` (voir `docs/guide-ajout-application-laravel.md`).

---

## 8. Dépannage

| Symptôme | Cause probable |
|---|---|
| « redirect_uri invalide pour ce client » (page IAM) | `IAM_OIDC_REDIRECT_URI` ≠ URI enregistrée (`http://localhost:8002/callback`), port compris. |
| « Un code_challenge PKCE S256 valide est obligatoire » | Appel de `oauth.php` sans PKCE : passer par `/login/oidc`. |
| « Échange de jeton refusé … invalid_client » | Mauvais `IAM_OIDC_CLIENT_SECRET` (voir § 3). |
| « Émetteur inattendu » | `IAM_BASE_URL` ≠ `IAM_BASE_URL` de `config/config.php` côté IAM (renseigner `IAM_OIDC_ISSUER`). |
| 403 « aucun rôle sur cette application » | Attribuer un rôle au compte dans l'IAM (Administration › Utilisateurs). |
| Déconnexion de l'autre application Laravel | Même `SESSION_COOKIE` dans les deux `.env`. |
| « state invalide ou expiré » | Plus de 10 minutes sur la page IAM, ou cookie de session perdu (voir ligne précédente). |
| Après une rotation JWKS dans l'IAM | Rien à faire : le JWKS est rechargé automatiquement au premier `kid` inconnu. |
