# Plan de captures — Guide d'utilisation IAM ACSI

Ce plan accompagne `docs/guide-utilisation-iam.md`. Les captures sont des fichiers PNG ignorés par Git (voir `.gitignore`). Seuls ce plan et `.gitkeep` sont versionnés, et le PDF du guide embarque les images.

## Règles

- **Nommage** : `XX-nom-court.png`, où `XX` est aussi le numéro de la figure dans le guide.
- **Format** : PNG, 1440 × 900 pixels, vue du navigateur sans barre d'adresse.
- **Données** : uniquement une instance de **démonstration** (données fictives), jamais la base de production.
- **Floutage** : mots de passe, codes OTP et secrets clients sont floutés avant la capture. Le script applique `filter: blur(5px)` sur les éléments indiqués.

## Production automatique

Les captures sont produites par `tools/guide/captures.mjs` (Node 22 ou plus, avec Chrome ou Edge).

**1. Préparer l'instance de démonstration.** Copier le projet dans `C:\wamp64\www\IAM-Guide-Demo`, sans `config/config.php`, `config/config.local.php` ni `.installed`, puis :

- lancer `install.php` avec le nom « IAM ACSI », une base dédiée (`iam_guide_demo`), un compte `admin@acsi.local` et les données de démonstration ;
- importer `sql/seed-app-partenaires.sql` et `sql/seed-app-stages-emplois.sql` en remplaçant `USE iam_local;` par `USE iam_guide_demo;`.

**2. Enregistrer le mot de passe administrateur** dans un fichier **hors du dépôt**. Les comptes de test reprennent ce mot de passe.

**3. Lancer les captures :**

```bash
IAM_GUIDE_BASE=http://localhost/IAM-Guide-Demo \
IAM_GUIDE_ROOT=C:/wamp64/www/IAM-Guide-Demo \
IAM_GUIDE_PASSWORD_FILE=/chemin/hors-depot/admin_pw.txt \
node tools/guide/captures.mjs            # toutes, ou : … captures.mjs 03 21
```

**4. Régénérer le PDF :** `bash tools/build-guide-pdf.sh`.

**5. Supprimer l'instance de démonstration** : le dossier et la base `iam_guide_demo`.

Comptes utilisés :

| Compte | Usage |
|---|---|
| `admin@acsi.local` | administrateur IAM, exempté de MFA |
| `gestionnaire.partenaires@acsi.local` | utilisateur avec rôle sur *Partenaires*, passe par la MFA |
| `gestionnaire.rh@aden.dz` | utilisateur **sans** rôle sur *Partenaires* (accès refusé) |
| `utilisateur.stages-emplois@acsi.local` | compte que l'on fait verrouiller (5 échecs) |

## Liste des captures

| Fichier | Écran / URL | Actions avant la capture | À flouter | Légende |
|---|---|---|---|---|
| `01-login.png` | `/login.php` | Aucune (déconnecté) | — | Figure 1 — Écran de connexion de l'IAM |
| `02-login-erreur.png` | `/login.php` | Saisir l'e-mail d'un compte de test et un mauvais mot de passe, valider | Champ mot de passe | Figure 2 — Message affiché après un mot de passe erroné |
| `03-mfa-saisie.png` | `/mfa.php` | Se connecter avec `gestionnaire.partenaires@…`, s'arrêter à la MFA | Code OTP du bandeau « Mode démonstration » | Figure 3 — Vérification en deux étapes : saisie du code reçu par e-mail |
| `04-compte-verrouille.png` | `/login.php` | 5 mots de passe faux sur `utilisateur.stages-emplois@…` | Champ mot de passe | Figure 4 — Compte verrouillé après 5 tentatives échouées |
| `05-portail.png` | `/portal.php` | Connexion complète (MFA) avec `gestionnaire.partenaires@…` | — | Figure 5 — Portail d'un utilisateur : une application accessible et son rôle |
| `06-profil.png` | `/profile.php` | Même compte | — | Figure 6 — Page « Mon profil » : identité, rôles et permissions |
| `07-profil-mot-de-passe.png` | `/profile.php` | Mot de passe actuel + nouveau mot de passe `abc` (deux fois), valider | Champs mot de passe | Figure 7 — Changement de mot de passe refusé : règles de la politique non respectées |
| `08-portail-administrateur.png` | `/portal.php` | Connexion `admin@acsi.local` | — | Figure 8 — Portail d'un administrateur : applications et accès à la console |
| `09-admin-tableau-de-bord.png` | `/admin/index.php` | Connexion admin | — | Figure 9 — Tableau de bord de la console d'administration |
| `10-admin-users-liste.png` | `/admin/users.php` | — | — | Figure 10 — Liste des utilisateurs : statut, rôles par application, dernière connexion |
| `11-admin-users-create.png` | `/admin/users.php` | « Nouvel utilisateur », remplir Awa Diallo / `awa.diallo@acsi.local` / AGT-0042 | Mot de passe temporaire | Figure 11 — Formulaire de création d'un utilisateur (mot de passe flouté) |
| `12-admin-users-edit.png` | `/admin/users.php?action=edit&id=4` | — | — | Figure 12 — Modification d'un utilisateur : identité, statut, rôles par application |
| `13-admin-users-reset-mdp.png` | `/admin/users.php` | Bouton « Mot de passe » de la première ligne | Champ nouveau mot de passe | Figure 13 — Réinitialisation du mot de passe par un administrateur |
| `14-admin-users-import-csv.png` | `/admin/users.php` | Bouton « Importer (CSV) » | — | Figure 14 — Import des utilisateurs à partir d'un fichier CSV |
| `15-admin-applications.png` | `/admin/apps.php` | — | — | Figure 15 — Liste des applications : permissions, accès utilisateurs, intégration SSO |
| `16-admin-applications-create.png` | `/admin/apps.php` | Faire défiler jusqu'à « Ajouter une application » | — | Figure 16 — Ajout d'une application SSO maison, étape « Application » |
| `17-admin-applications-integration-sso.png` | `/admin/apps.php` | Bouton « Intégration SSO » de la première application | — | Figure 17 — Intégration SSO automatique : fichier généré à déposer dans l'application |
| `18-admin-oidc-liste.png` | `/admin/oidc_apps.php` | — | — | Figure 18 — Liste des applications OAuth / OIDC |
| `19-admin-oidc-wizard-plateforme.png` | `/admin/oidc_wizard.php` | — | — | Figure 19 — Assistant OIDC : choix de la plateforme et informations générales |
| `20-admin-oidc-wizard-configuration.png` | `/admin/oidc_wizard.php` | Nom « Gestion des congés », slug `conges`, URL `http://localhost:8003`, « Continuer » | — | Figure 20 — Assistant OIDC : redirect URIs, scopes et grant types |
| `21-admin-oidc-detail.png` | `/admin/oidc_apps.php?view=1` | — | Tout champ de secret, s'il y en a un | Figure 21 — Fiche d'une application OIDC : configuration, client ID, actions |
| `22-admin-roles.png` | `/admin/roles.php` | — | — | Figure 22 — Rôles par application |
| `23-admin-roles-permissions.png` | `/admin/roles.php` | Bouton « Permissions » du premier rôle | — | Figure 23 — Attribution des permissions à un rôle |
| `24-admin-applications-permissions.png` | `/admin/apps.php` | Bouton « Permissions (25) » de *Partenaires* | — | Figure 24 — Catalogue des permissions d'une application |
| `25-admin-applications-acces.png` | `/admin/apps.php` | Bouton « Accès utilisateurs (3) » de *Partenaires* | — | Figure 25 — Utilisateurs autorisés sur une application et leur rôle |
| `26-admin-organisations.png` | `/admin/organizations.php` | — | — | Figure 26 — Structure organisationnelle et formulaire « Nouvelle organisation » |
| `27-admin-groupes.png` | `/admin/groups.php` | Bouton « Nouveau groupe » | — | Figure 27 — Création d'un groupe d'utilisateurs |
| `28-admin-audit.png` | `/admin/audit.php` | — | — | Figure 28 — Journal d'audit |
| `29-admin-sessions.png` | `/admin/sessions.php` | — | — | Figure 29 — Sessions actives et révocation |
| `30-admin-parametres.png` | `/admin/settings.php` | — | — | Figure 30 — Paramètres : politique de mot de passe et sécurité de l'API |
| `31-admin-email-mfa.png` | `/admin/email.php` | — | Mot de passe SMTP | Figure 31 — Configuration de l'envoi des codes MFA (mot de passe flouté) |
| `32-oauth-consentement.png` | `/oauth.php?client_id=iam-laravel-partenaires&…` (PKCE S256) | Connexion complète avec `gestionnaire.partenaires@…` | — | Figure 32 — Consentement OAuth 2.0 / OIDC avant l'ouverture de l'application |
| `33-oauth-acces-refuse.png` | Même URL | Connexion complète avec `gestionnaire.rh@aden.dz` (sans rôle) | — | Figure 33 — Accès refusé : utilisateur connecté mais sans rôle sur l'application |

Le schéma d'architecture (Schéma 1) n'est pas une capture. C'est un fichier vectoriel versionné : `docs/images/architecture-iam.svg`.

## Défauts d'affichage constatés pendant les captures

Ces défauts existaient déjà dans l'IAM. Ils sont visibles sur les captures et n'ont pas été corrigés.

- **Figures 21, 24 et 26** : des colonnes de tableau trop étroites affichent le texte lettre par lettre. Le défaut persiste à 1680 px de large.
- **Figure 31** : le titre de la page affiche `E-mail &amp; MFA` (double échappement HTML).
