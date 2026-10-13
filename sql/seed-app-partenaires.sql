-- ============================================================
--  IAM-LOCAL — Application Laravel « Gestion des Partenaires » (partenaires)
-- ============================================================
--  URL de l'application : http://localhost:8001
--  Client OIDC          : iam-laravel-partenaires (confidentiel, PKCE S256 obligatoire)
--  Redirect URI         : http://localhost:8001/callback
--  Post-logout URI      : http://localhost:8001/logged-out
--
--  Contenu :
--    1. fiche application (table applications)
--    2. client OAuth2/OIDC (table oauth_clients) : redirect_uri, PKCE, scopes
--    3. catalogue de 25 permissions (5 modules × 5 actions)
--       codes préfixés par le code de l'application, car
--       permissions.code est UNIQUE sur toute la plateforme
--    4. trois rôles LOCAUX : admin, gestionnaire, utilisateur
--    5. matrice rôles × permissions (reconstruite à chaque passage)
--    6. trois comptes de test, un par rôle
--
--  IDEMPOTENT : peut être rejoué sans dupliquer ni casser l'existant.
--    - tout est résolu par CODE (application, rôle, permission,
--      e-mail), jamais par identifiant numérique ;
--    - un second passage NE modifie PAS : l'URL de l'application,
--      son état actif/inactif, sa couleur et son icône, le secret
--      du client OIDC (une rotation faite dans l'admin est conservée),
--      ni le mot de passe des comptes de test ;
--    - un second passage RÉTABLIT la matrice rôles × permissions de
--      référence ci-dessous (comme sql/seed-roles-matrix.sql).
--
--  Aucun placeholder : exécutable tel quel dans phpMyAdmin ou par
--    mysql -u root iam_local < sql/seed-app-partenaires.sql
--  Prérequis : install.php exécuté (compte admin + application iam-admin).
--
--  SECRET CLIENT DE DÉVELOPPEMENT
--    dev-partenaires-b27e6f971de7b05bc643851c3840f025
--  À copier dans IAM_OIDC_CLIENT_SECRET du .env Laravel.
--  Valable uniquement en local : avant tout autre usage, régénérez-le
--  dans Administration > Applications OAuth / OIDC > Régénérer le secret.
--
--  MOT DE PASSE DES COMPTES DE TEST : identique à celui des comptes de
--  démonstration (seed-demo.sql), c'est-à-dire le mot de passe du
--  premier administrateur actif de l'IAM au moment de l'import.
-- ============================================================

USE iam_local;

-- ------------------------------------------------------------
-- 1. Fiche application
--    sso_prompt = 0 : connexion transparente si une session IAM
--    est déjà ouverte (comportement des applications OIDC).
-- ------------------------------------------------------------
INSERT INTO applications (code, name, description, url, color, icon, client_id, redirect_uri, scopes, active, sso_prompt, is_system)
VALUES ('partenaires', 'Gestion des Partenaires', 'Suivi des partenaires, de leurs contacts, conventions et documents',
        'http://localhost:8001', '#0b6e4f', 'fa-handshake', 'iam-laravel-partenaires',
        'http://localhost:8001/callback', 'openid profile email roles offline_access', 1, 0, 0)
ON DUPLICATE KEY UPDATE
  name         = VALUES(name),
  description  = VALUES(description),
  client_id    = VALUES(client_id),
  redirect_uri = VALUES(redirect_uri),
  scopes       = VALUES(scopes);

-- ------------------------------------------------------------
-- 2. Client OAuth2 / OIDC
--    Confidentiel (Laravel garde le secret côté serveur) ET PKCE
--    S256 obligatoire (pkce_required = 1) : défense en profondeur
--    contre l'interception du code d'autorisation.
--    Le secret est stocké haché (bcrypt), comme le fait l'admin.
-- ------------------------------------------------------------
--    Rejeu : la configuration de référence est rétablie, SAUF le
--    secret (une rotation faite dans l'admin est conservée) et
--    l'état actif/inactif.
-- ------------------------------------------------------------
INSERT INTO oauth_clients
  (application_id, name, slug, description, platform, platform_version, client_type,
   client_id, client_secret, redirect_uris, post_logout_uris, scopes, grant_types,
   token_lifetime, refresh_lifetime, base_url, is_active, refresh_enabled,
   pkce_required, role_mappings, jit_provisioning)
VALUES ((SELECT id FROM applications WHERE code = 'partenaires'),
        'Gestion des Partenaires', 'partenaires', 'Suivi des partenaires, de leurs contacts, conventions et documents', 'laravel', '11', 'confidential',
        'iam-laravel-partenaires',
        '$2y$10$ZS22ALoUgzotJbLgBQxezuKsM730DywmVK44kTS1bXEqzxWeSMeHq',
        JSON_ARRAY('http://localhost:8001/callback'),
        JSON_ARRAY('http://localhost:8001/logged-out'),
        JSON_ARRAY('openid', 'profile', 'email', 'roles', 'offline_access'),
        JSON_ARRAY('authorization_code', 'refresh_token'),
        3600, 2592000, 'http://localhost:8001', 1, 1, 1, NULL, 0)
ON DUPLICATE KEY UPDATE
  application_id   = VALUES(application_id),
  platform         = VALUES(platform),
  platform_version = VALUES(platform_version),
  client_type      = VALUES(client_type),
  redirect_uris    = VALUES(redirect_uris),
  post_logout_uris = VALUES(post_logout_uris),
  scopes           = VALUES(scopes),
  grant_types      = VALUES(grant_types),
  refresh_enabled  = VALUES(refresh_enabled),
  pkce_required    = VALUES(pkce_required);

-- ------------------------------------------------------------
-- 3. Catalogue des permissions (25)
--    Rejeu : libellés et rattachement mis à jour, code inchangé.
-- ------------------------------------------------------------
INSERT INTO permissions (application_id, name, code, description) VALUES
  ((SELECT id FROM applications WHERE code = 'partenaires'), 'Voir les partenaires', 'partenaires.partenaires.view', 'Consulter les partenaires (lecture seule)'),
  ((SELECT id FROM applications WHERE code = 'partenaires'), 'Créer un partenaire', 'partenaires.partenaires.create', 'Ajouter un partenaire'),
  ((SELECT id FROM applications WHERE code = 'partenaires'), 'Modifier un partenaire', 'partenaires.partenaires.edit', 'Modifier un partenaire existant(e)'),
  ((SELECT id FROM applications WHERE code = 'partenaires'), 'Supprimer un partenaire', 'partenaires.partenaires.delete', 'Supprimer définitivement un partenaire'),
  ((SELECT id FROM applications WHERE code = 'partenaires'), 'Exporter les partenaires', 'partenaires.partenaires.export', 'Exporter les partenaires (CSV, Excel, PDF)'),
  ((SELECT id FROM applications WHERE code = 'partenaires'), 'Voir les contacts', 'partenaires.contacts.view', 'Consulter les contacts (lecture seule)'),
  ((SELECT id FROM applications WHERE code = 'partenaires'), 'Créer un contact', 'partenaires.contacts.create', 'Ajouter un contact'),
  ((SELECT id FROM applications WHERE code = 'partenaires'), 'Modifier un contact', 'partenaires.contacts.edit', 'Modifier un contact existant(e)'),
  ((SELECT id FROM applications WHERE code = 'partenaires'), 'Supprimer un contact', 'partenaires.contacts.delete', 'Supprimer définitivement un contact'),
  ((SELECT id FROM applications WHERE code = 'partenaires'), 'Exporter les contacts', 'partenaires.contacts.export', 'Exporter les contacts (CSV, Excel, PDF)'),
  ((SELECT id FROM applications WHERE code = 'partenaires'), 'Voir les conventions', 'partenaires.conventions.view', 'Consulter les conventions (lecture seule)'),
  ((SELECT id FROM applications WHERE code = 'partenaires'), 'Créer une convention', 'partenaires.conventions.create', 'Ajouter une convention'),
  ((SELECT id FROM applications WHERE code = 'partenaires'), 'Modifier une convention', 'partenaires.conventions.edit', 'Modifier une convention existant(e)'),
  ((SELECT id FROM applications WHERE code = 'partenaires'), 'Supprimer une convention', 'partenaires.conventions.delete', 'Supprimer définitivement une convention'),
  ((SELECT id FROM applications WHERE code = 'partenaires'), 'Exporter les conventions', 'partenaires.conventions.export', 'Exporter les conventions (CSV, Excel, PDF)'),
  ((SELECT id FROM applications WHERE code = 'partenaires'), 'Voir les documents', 'partenaires.documents.view', 'Consulter les documents (lecture seule)'),
  ((SELECT id FROM applications WHERE code = 'partenaires'), 'Créer un document', 'partenaires.documents.create', 'Ajouter un document'),
  ((SELECT id FROM applications WHERE code = 'partenaires'), 'Modifier un document', 'partenaires.documents.edit', 'Modifier un document existant(e)'),
  ((SELECT id FROM applications WHERE code = 'partenaires'), 'Supprimer un document', 'partenaires.documents.delete', 'Supprimer définitivement un document'),
  ((SELECT id FROM applications WHERE code = 'partenaires'), 'Exporter les documents', 'partenaires.documents.export', 'Exporter les documents (CSV, Excel, PDF)'),
  ((SELECT id FROM applications WHERE code = 'partenaires'), 'Voir les rapports', 'partenaires.rapports.view', 'Consulter les rapports (lecture seule)'),
  ((SELECT id FROM applications WHERE code = 'partenaires'), 'Créer un rapport', 'partenaires.rapports.create', 'Ajouter un rapport'),
  ((SELECT id FROM applications WHERE code = 'partenaires'), 'Modifier un rapport', 'partenaires.rapports.edit', 'Modifier un rapport existant(e)'),
  ((SELECT id FROM applications WHERE code = 'partenaires'), 'Supprimer un rapport', 'partenaires.rapports.delete', 'Supprimer définitivement un rapport'),
  ((SELECT id FROM applications WHERE code = 'partenaires'), 'Exporter les rapports', 'partenaires.rapports.export', 'Exporter les rapports (CSV, Excel, PDF)')
ON DUPLICATE KEY UPDATE
  application_id = VALUES(application_id),
  name           = VALUES(name),
  description    = VALUES(description);

-- ------------------------------------------------------------
-- 4. Rôles locaux (application_id renseigné, is_system = 0)
--    is_system = 0 : le rôle « admin » de cette application ne
--    donne AUCUN droit sur la console IAM (iam_user_is_admin).
--    Clé unique (application_id, code) : rejouable.
-- ------------------------------------------------------------
INSERT INTO roles (application_id, name, code, description, is_system) VALUES
  ((SELECT id FROM applications WHERE code = 'partenaires'), 'Administrateur', 'admin', 'Accès complet à l''application : lecture, création, modification, suppression, export', 0),
  ((SELECT id FROM applications WHERE code = 'partenaires'), 'Gestionnaire', 'gestionnaire', 'Gère les données au quotidien : lecture, création, modification, export ; pas de suppression', 0),
  ((SELECT id FROM applications WHERE code = 'partenaires'), 'Utilisateur', 'utilisateur', 'Consultation seule de tous les modules', 0)
ON DUPLICATE KEY UPDATE
  name        = VALUES(name),
  description = VALUES(description);

-- ------------------------------------------------------------
-- 5. Matrice rôles × permissions (référence, à valider)
--
--                 view  create  edit  delete  export
--   admin           x      x       x      x       x   
--   gestionnaire    x      x       x      .       x   
--   utilisateur     x      .       .      .       .   
--   (identique pour chaque module)
--
--    On efface d'abord les droits des trois rôles de CETTE
--    application, puis on les reconstruit : un droit retiré ici
--    disparaît aussi de la base au passage suivant.
-- ------------------------------------------------------------
DELETE rp FROM role_permissions rp
  JOIN roles r        ON r.id = rp.role_id
  JOIN applications a ON a.id = r.application_id
 WHERE a.code = 'partenaires'
   AND r.code IN ('admin', 'gestionnaire', 'utilisateur');

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
  FROM applications a
  JOIN roles r       ON r.application_id = a.id
  JOIN permissions p ON p.application_id = a.id
 WHERE a.code = 'partenaires'
   AND (
        (r.code = 'admin' AND SUBSTRING_INDEX(p.code, '.', -1) IN ('view', 'create', 'edit', 'delete', 'export'))
     OR (r.code = 'gestionnaire' AND SUBSTRING_INDEX(p.code, '.', -1) IN ('view', 'create', 'edit', 'export'))
     OR (r.code = 'utilisateur' AND SUBSTRING_INDEX(p.code, '.', -1) IN ('view'))
   );

-- ------------------------------------------------------------
-- 6. Comptes de test (un par rôle)
--    Mot de passe = celui du premier administrateur actif de
--    l'application iam-admin, comme seed-demo.sql.
--    must_change_password = 0 pour pouvoir dérouler les tests.
--    Second passage : le compte existe déjà (e-mail ou identifiant), il
--    n'est pas modifié — mot de passe et statut sont conservés.
-- ------------------------------------------------------------
INSERT INTO users (username, email, phone, password_hash, first_name, last_name, status, mfa_enabled, must_change_password)
SELECT t.username, t.email, '', adm.password_hash, t.first_name, t.last_name, 'active', 0, 0
  FROM (
        SELECT 'admin.partenaires' AS username, 'admin.partenaires@acsi.local' AS email, 'Admin' AS first_name, 'Partenaires' AS last_name
  UNION ALL SELECT 'gestionnaire.partenaires', 'gestionnaire.partenaires@acsi.local', 'Gestionnaire', 'Partenaires'
  UNION ALL SELECT 'utilisateur.partenaires', 'utilisateur.partenaires@acsi.local', 'Utilisateur', 'Partenaires'
  ) t
  CROSS JOIN (SELECT u.password_hash
          FROM users u
          JOIN user_roles ur   ON ur.user_id = u.id
          JOIN roles r         ON r.id = ur.role_id AND r.code = 'admin'
          JOIN applications ia ON ia.id = ur.application_id AND ia.code = 'iam-admin'
         WHERE u.status = 'active'
         ORDER BY u.id LIMIT 1) adm
 WHERE NOT EXISTS (SELECT 1 FROM users x WHERE x.email = t.email OR x.username = t.username);

INSERT INTO password_history (user_id, password_hash)
SELECT u.id, u.password_hash
  FROM users u
 WHERE u.email IN ('admin.partenaires@acsi.local', 'gestionnaire.partenaires@acsi.local', 'utilisateur.partenaires@acsi.local')
   AND NOT EXISTS (SELECT 1 FROM password_history ph WHERE ph.user_id = u.id);

-- Un seul rôle par compte, sur CETTE application uniquement.
INSERT INTO user_roles (user_id, role_id, application_id)
SELECT u.id, r.id, a.id
  FROM applications a
  JOIN roles r ON r.application_id = a.id
  JOIN users u ON u.email = CONCAT(r.code, '.', a.code, '@acsi.local')
 WHERE a.code = 'partenaires'
   AND r.code IN ('admin', 'gestionnaire', 'utilisateur')
   AND NOT EXISTS (SELECT 1 FROM user_roles x
                    WHERE x.user_id = u.id AND x.role_id = r.id AND x.application_id = a.id);

-- ------------------------------------------------------------
-- Contrôle (lecture seule) : nombre de droits par rôle
--   attendu : admin 25, gestionnaire 20, utilisateur 5
-- ------------------------------------------------------------
SELECT r.code AS role, COUNT(rp.permission_id) AS permissions
  FROM roles r
  JOIN applications a ON a.id = r.application_id
  LEFT JOIN role_permissions rp ON rp.role_id = r.id
 WHERE a.code = 'partenaires'
 GROUP BY r.code ORDER BY r.code;
