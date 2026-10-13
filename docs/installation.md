# Installation de l'IAM-Local

## 1. Prérequis

- Serveur web Apache avec `mod_rewrite` (WampServer convient) ;
- PHP 8.1 ou plus récent, avec les extensions `pdo_mysql`, `openssl`, `curl`, `mbstring` et `dom` ;
- MySQL 8 ou MariaDB 10.5 ou plus récent ;
- Composer, si l'envoi des codes MFA passe par PHPMailer (`composer install` à la racine).

## 2. Installation neuve

1. Copier le projet dans le dossier web, par exemple `C:\wamp64\www\IAM-Local`.
2. Ouvrir `http://localhost/IAM-Local/install.php`.
3. Renseigner :
   - le nom de la plateforme et l'URL de base (détectée automatiquement) ;
   - la connexion MySQL (hôte, utilisateur, mot de passe, base, port) ;
   - le compte administrateur. Si le mot de passe est laissé vide, un mot de passe est généré et affiché une seule fois ;
   - les données de démonstration (facultatives).
4. Valider. L'installateur :
   - crée la base et applique `sql/schema.sql`, puis `sql/seed.sql` et, si demandé, `sql/seed-demo.sql` ;
   - écrit **`config/config.php`**, une copie complète de `config/config.template.php` qui contient toutes les constantes ;
   - écrit **`config/config.local.php`**, qui contient les secrets : accès MySQL, clé JWT générée aléatoirement, identifiants SMTP vides ;
   - régénère `.htaccess` et crée le fichier `.installed`.
5. Se connecter avec le compte administrateur.

> `config/config.php` et `config/config.local.php` ne sont **pas versionnés** (`.gitignore`). Seul le modèle `config/config.template.php` l'est.

## 3. Les fichiers de configuration

| Fichier | Versionné | Contenu |
|---|---|---|
| `config/config.template.php` | oui | Référence de **toutes** les constantes, avec leurs valeurs par défaut commentées |
| `config/config.php` | non | Configuration de l'instance (générée depuis le modèle) |
| `config/config.local.php` | non | Secrets : `DB_*`, `IAM_JWT_SECRET`, `SMTP_USER`, `SMTP_PASS`, secrets OAuth des fournisseurs mail |

`config.php` charge `config.local.php` en premier. Toute constante définie dans `config.local.php` l'emporte sur la valeur par défaut de `config.php`.

### Principales constantes

| Constante | Défaut | Rôle |
|---|---|---|
| `MFA_FORCE_ALL` | `true` | Code MFA par e-mail exigé à la connexion pour tous les comptes **non administrateurs** |
| `MFA_EXEMPT_ADMINS` | `true` | Informatif : les administrateurs IAM sont exemptés de la MFA. L'exemption est codée dans `login.php`, `api/login.php` et `oauth.php`. **C'est un choix volontaire, à ne pas modifier.** |
| `MFA_CODE_TTL` (→ `OTP_LIFETIME`) | `300` | Validité du code MFA, en secondes |
| `MFA_MAX_ATTEMPTS` (→ `OTP_MAX_TRIES`) | `5` | Nombre d'essais de saisie du code MFA |
| `SESSION_IDLE_TIMEOUT` (→ `IDLE_TIMEOUT`) | `1800` | Déconnexion après inactivité, en secondes |
| `LOGIN_MAX_ATTEMPTS` (→ `MAX_LOGIN_ATTEMPTS`) | `5` | Échecs de connexion avant blocage |
| `LOGIN_LOCKOUT_MINUTES` (→ `LOCKOUT_MINUTES`) | `30` | Durée du blocage, en minutes |
| `PASSWORD_HISTORY_SIZE` | `5` | Valeur de référence. La valeur effective est dans la table `password_policy` |
| `PASSWORD_EXPIRY_DAYS` | `90` | Valeur de référence. La valeur effective est dans la table `password_policy` |

Les noms entre parenthèses sont ceux que lit le code. Dans le modèle, ils sont définis à partir des noms documentés : `define('OTP_LIFETIME', MFA_CODE_TTL);`.

## 4. Contrôle d'intégrité au démarrage

Chaque page charge la configuration par `includes/config_bootstrap.php`, qui appelle `iam_check_config_integrity()`. Le contrôle échoue dans trois cas :

- `config/config.php` est absent ;
- une constante attendue manque (la liste est dans `includes/config_constants.php`) ;
- `IAM_BASE_URL`, `DB_HOST`, `DB_NAME` ou `IAM_JWT_SECRET` est vide, ce qui arrive typiquement quand `config.local.php` est absent.

Dans ces cas, l'IAM répond :

- dans le navigateur : une page « Configuration de l'IAM incomplète » (HTTP 500), avec la liste des problèmes et un lien vers `install.php` ;
- sur `/api/…` : `{"error":"server_misconfigured","missing":[…]}` (HTTP 500) ;
- en ligne de commande : la liste sur la sortie d'erreur, avec le code de sortie 1.

Pour corriger, deux possibilités :

- relancer l'installateur, après avoir supprimé le fichier `.installed` ;
- compléter `config/config.php` à partir de `config/config.template.php`, et `config/config.local.php` pour les secrets.

## 5. Mise à jour d'une installation existante

Une installation antérieure à la version 1.0.3 continue de fonctionner sans modification, tant que son `config.php` contient les 33 constantes attendues. La page de contrôle signale celles qui manquent. Pour isoler les secrets :

1. créer `config/config.local.php` avec `DB_*` et `IAM_JWT_SECRET` (modèle : section 3) ;
2. dans `config/config.php`, ajouter en tête :
   `if (is_file(__DIR__ . '/config.local.php')) { require_once __DIR__ . '/config.local.php'; }` ;
3. dans `config/config.php`, remplacer chaque `define('DB_HOST', …)` par `defined('DB_HOST') || define('DB_HOST', …)`, et faire de même pour les autres secrets.

## 6. Vérifier l'installation

Commandes à lancer depuis la racine de l'IAM :

```bash
php -r "require 'includes/functions.php'; echo 'configuration OK', PHP_EOL;"
php tools/tests/test_oauth_securite.php
```

Le premier test affiche la liste des constantes manquantes s'il y en a. Le second rejoue les flux OAuth avec des données temporaires.

Test manuel de première connexion :

- un **administrateur** arrive sur le portail **sans** code MFA ;
- un **compte non administrateur** passe par `mfa.php`, puisque `MFA_FORCE_ALL = true`.

Ces deux parcours ont été vérifiés le 2026-10-13 sur une installation neuve (base dédiée, données de démonstration).
