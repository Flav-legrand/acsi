<?php
// IAM-Local — API REST : GET|POST /api/users.php — CRUD utilisateurs
require_once __DIR__ . '/../includes/functions.php';

$user = api_require_auth();

// Vérifier que l'utilisateur est admin global ou a la permission users.manage
if (!iam_user_is_admin((int) $user['id']) && !iam_user_has_permission((int) $user['id'], 'users.manage')) {
    api_json_response(['error' => 'Permission insuffisante.'], 403);
}

$db = db();
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

// GET — Lister les utilisateurs
if ($method === 'GET') {
    $page    = max(1, (int) input('page', 1));
    $perPage = min(100, max(1, (int) input('per_page', 20)));
    $search  = input('search', '');
    $offset  = ($page - 1) * $perPage;

    $where  = '';
    $params = [];
    if ($search !== '') {
        $where = 'WHERE (u.email LIKE ? OR u.username LIKE ? OR u.first_name LIKE ? OR u.last_name LIKE ?)';
        $s = "%$search%";
        $params = [$s, $s, $s, $s];
    }

    $stmtCount = $db->prepare("SELECT COUNT(*) FROM users u $where");
    $stmtCount->execute($params);
    $total = (int) $stmtCount->fetchColumn();

    $sql = "SELECT u.id, u.username, u.email, u.phone, u.first_name, u.last_name, u.matricule,
                   u.status, u.mfa_enabled, u.last_login_at, u.created_at,
                   o.name AS organization_name
            FROM users u
            LEFT JOIN organizations o ON o.id = u.organization_id
            $where
            ORDER BY u.last_name, u.first_name
            LIMIT ? OFFSET ?";
    $params[] = $perPage;
    $params[] = $offset;
    $stmt = $db->prepare($sql);
    $stmt->execute($params);

    api_json_response([
        'users'     => $stmt->fetchAll(),
        'total'     => $total,
        'page'      => $page,
        'per_page'  => $perPage,
        'last_page' => ceil($total / $perPage),
    ]);
}

// POST — Créer un utilisateur
if ($method === 'POST') {
    $body = api_request_body();
    $email     = trim($body['email'] ?? '');
    $username  = trim($body['username'] ?? $email);
    $password  = $body['password'] ?? '';
    $firstName = trim($body['first_name'] ?? '');
    $lastName  = trim($body['last_name'] ?? '');
    $phone     = trim($body['phone'] ?? '');
    $matricule = trim($body['matricule'] ?? '');
    $orgId     = !empty($body['organization_id']) ? (int) $body['organization_id'] : null;
    $rolesApps = $body['roles'] ?? [];  // [{role_id, app_id}, ...]

    if (empty($email) || empty($firstName) || empty($lastName)) {
        api_json_response(['error' => 'email, first_name et last_name requis.'], 422);
    }

    $policy = iam_get_password_policy();
    if (empty($password)) {
        // Générer un mot de passe temporaire
        $password = substr(str_replace(['/', '+', '='], '', base64_encode(random_bytes(8))), 0, 12) . 'A1!';
    } else {
        $pwErrors = iam_validate_password($password, $policy);
        if (!empty($pwErrors)) {
            api_json_response(['error' => 'Mot de passe invalide.', 'details' => $pwErrors], 422);
        }
    }

    // Vérifier unicité email
    $stmt = $db->prepare('SELECT id FROM users WHERE email = ? LIMIT 1');
    $stmt->execute([$email]);
    if ($stmt->fetch()) {
        api_json_response(['error' => 'Un compte avec cet email existe déjà.'], 409);
    }

    $hash = iam_hash_password($password);
    $stmt = $db->prepare('INSERT INTO users (username, email, phone, password_hash, first_name, last_name, matricule, organization_id, must_change_password, created_by, created_at)
                          VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, NOW())');
    $stmt->execute([$username, $email, $phone, $hash, $firstName, $lastName, $matricule, $orgId, (int) $user['id']]);
    $newUserId = (int) $db->lastInsertId();

    // Enregistrer dans l'historique
    $db->prepare('INSERT INTO password_history (user_id, password_hash) VALUES (?, ?)')->execute([$newUserId, $hash]);

    // Assigner les rôles
    if (is_array($rolesApps)) {
        $insertRole = $db->prepare('INSERT IGNORE INTO user_roles (user_id, role_id, application_id) VALUES (?, ?, ?)');
        foreach ($rolesApps as $ra) {
            $rid = (int) $ra['role_id'];
            $aid = (int) $ra['app_id'];
            if ($rid > 0 && $aid > 0 && iam_role_allowed_for_app($rid, $aid)) $insertRole->execute([$newUserId, $rid, $aid]);
        }
    }

    iam_audit('user_created', "Utilisateur créé: $email", (int) $user['id'], $user['email'], $_SERVER['REMOTE_ADDR'] ?? '', $_SERVER['HTTP_USER_AGENT'] ?? '');

    api_json_response(['success' => true, 'user_id' => $newUserId, 'temporary_password' => $password], 201);
}
