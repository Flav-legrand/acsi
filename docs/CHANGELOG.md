# Journal des modifications — IAM-Local

Format : une entrée par correctif, la plus récente en haut.
Aucune des failles ci-dessous n'a fait l'objet d'une référence CVE : elles ont été relevées en revue interne avant toute diffusion publique.

## [1.0.1] — 2026-10-13

### Sécurité — `oauth.php` délivrait un code sans vérifier les rôles

- **Faille** : tout utilisateur authentifié à l'IAM obtenait un code d'autorisation OAuth 2.0 / OIDC pour n'importe quel client actif, même sans aucun rôle sur l'application liée.
- **Correctif** : nouvelle fonction `iam_user_has_role_on_application()` (`includes/functions.php`), appelée dans `oauth.php` avant le consentement et avant l'émission du code. Sans rôle : écran « Accès refusé » (403), retour `redirect_uri?error=access_denied&state=…`, aucun code émis, audit `oauth_authorize_denied` (`raison = no_role_on_application`).
- **Impact** : l'administrateur IAM n'est plus exempté pour OAuth/OIDC (le SSO maison n'est pas modifié). Applications de test partenaires et stages-emplois : aucun impact pour les comptes qui ont un rôle.
- **Vérification** : `php tools/tests/test_oauth_securite.php`
- **Référence** : RFC 6749 §4.1.2.1 ; CVE : aucune.
