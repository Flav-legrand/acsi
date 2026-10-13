# Journal des modifications — IAM-Local

Format : une entrée par correctif, la plus récente en haut.
Aucune des failles ci-dessous n'a fait l'objet d'une référence CVE : elles ont été relevées en revue interne avant toute diffusion publique.

## [1.0.2] — 2026-10-13

### Sécurité — renouvellement de jeton sans vérification du secret client

- **Faille** : `grant_type=refresh_token` (`api/oauth/token.php`) n'authentifiait pas le client : un refresh token volé suffisait pour obtenir de nouveaux jetons. `api/refresh.php` acceptait aussi les refresh tokens OAuth.
- **Correctif** : authentification obligatoire du client confidentiel (Basic ou corps POST), `client_id` du jeton = client authentifié (sinon `invalid_grant`), rotation atomique du refresh token et révocation de la lignée en cas de rejeu. `api/refresh.php` limité aux jetons du SSO maison. Échecs audités : `oauth_refresh_failed` (`invalid_client_secret` | `client_mismatch` | `token_reuse`).
- **Impact** : applications de test partenaires et stages-emplois inchangées si leur secret est correct. Un renouvellement concurrent avec le même jeton ferme désormais la session.
- **Vérification** : `php tools/tests/test_oauth_securite.php`
- **Référence** : RFC 6749 §6, RFC 6819 §5.2.2.3 ; CVE : aucune.

## [1.0.1] — 2026-10-13

### Sécurité — `oauth.php` délivrait un code sans vérifier les rôles

- **Faille** : tout utilisateur authentifié à l'IAM obtenait un code d'autorisation OAuth 2.0 / OIDC pour n'importe quel client actif, même sans aucun rôle sur l'application liée.
- **Correctif** : nouvelle fonction `iam_user_has_role_on_application()` (`includes/functions.php`), appelée dans `oauth.php` avant le consentement et avant l'émission du code. Sans rôle : écran « Accès refusé » (403), retour `redirect_uri?error=access_denied&state=…`, aucun code émis, audit `oauth_authorize_denied` (`raison = no_role_on_application`).
- **Impact** : l'administrateur IAM n'est plus exempté pour OAuth/OIDC (le SSO maison n'est pas modifié). Applications de test partenaires et stages-emplois : aucun impact pour les comptes qui ont un rôle.
- **Vérification** : `php tools/tests/test_oauth_securite.php`
- **Référence** : RFC 6749 §4.1.2.1 ; CVE : aucune.
