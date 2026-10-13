<?php
/**
 * IAM-Local — Installateur
 * Exécution unique : configuration BDD, schéma, données, marquage installé.
 * Générique : URL de base auto-détectée, marque et identifiants admin configurables,
 * données de démonstration optionnelles (seed-demo.sql).
 */

session_start();

// ── Chemins ──────────────────────────────────────────────────
$root         = __DIR__;
$flagFile     = $root . '/.installed';
$configDir    = $root . '/config';
$configFile   = $configDir . '/config.php';
$schemaFile   = $root . '/sql/schema.sql';
$seedFile     = $root . '/sql/seed.sql';
$demoFile     = $root . '/sql/seed-demo.sql';
$htaccessFile = $root . '/.htaccess';

// ── Helpers ──────────────────────────────────────────────────
function esc(string $v): string {
    return htmlspecialchars($v, ENT_QUOTES, 'UTF-8');
}

function install_is_done(string $flagFile): bool {
    return file_exists($flagFile);
}

/**
 * Auto-détection de l'URL de base (protocole + hôte + dossier courant).
 */
function install_detect_base_url(): string {
    $https = (!empty($_SERVER['HTTPS']) && strtolower($_SERVER['HTTPS']) !== 'off')
          || ($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https';
    $proto = $https ? 'https' : 'http';
    $host  = $_SERVER['HTTP_HOST'] ?? 'localhost';
    $dir   = rtrim(str_replace('\\', '/', dirname($_SERVER['SCRIPT_NAME'] ?? '/install.php')), '/');
    return $proto . '://' . $host . $dir;
}

/**
 * Extrait le chemin de dossier (ex: "/IAM-Local") depuis une URL de base.
 */
function install_detect_base_path(string $baseUrl): string {
    $path = parse_url($baseUrl, PHP_URL_PATH) ?? '';
    return rtrim($path, '/') ?: '';
}

/**
 * Génère un mot de passe conforme à la politique par défaut (maj, min, chiffre, spécial).
 */
function install_generate_password(): string {
    $token = str_pad((string) random_int(0, 9999), 4, '0', STR_PAD_LEFT);
    return 'Admin@' . $token;
}

function install_can_connect(string $host, string $user, string $pass, int $port = 3306): ?PDO {
    try {
        $dsn = 'mysql:host=' . $host . ';port=' . $port . ';charset=utf8mb4';
        return new PDO($dsn, $user, $pass, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        ]);
    } catch (PDOException $e) {
        return null;
    }
}

function install_tables_exist(PDO $pdo, string $dbName): bool {
    try {
        $stmt = $pdo->prepare('SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = ?');
        $stmt->execute([$dbName]);
        return (int) $stmt->fetchColumn() > 0;
    } catch (PDOException $e) {
        return false;
    }
}

/**
 * Exécute du SQL découpé par points-virgules, sans commentaires.
 * Erreurs "table/colonne/clé déjà existante" ignorées -> idempotent.
 */
function install_split_sql(string $sql): array {
    $statements = [];
    $cur = '';
    $len = strlen($sql);
    $inS = $inD = $inB = $inLine = $inBlock = false;
    for ($i = 0; $i < $len; $i++) {
        $ch   = $sql[$i];
        $next = $i + 1 < $len ? $sql[$i + 1] : '';
        if ($inLine)  { if ($ch === "\n") { $inLine = false; $cur .= $ch; } continue; }
        if ($inBlock) { if ($ch === '*' && $next === '/') { $inBlock = false; $i++; } continue; }
        if ($inS) {
            $cur .= $ch;
            if ($ch === '\\') { if ($next !== '') { $cur .= $next; $i++; } continue; }
            if ($ch === "'") { if ($next === "'") { $cur .= $next; $i++; } else { $inS = false; } }
            continue;
        }
        if ($inD) {
            $cur .= $ch;
            if ($ch === '\\') { if ($next !== '') { $cur .= $next; $i++; } continue; }
            if ($ch === '"') { if ($next === '"') { $cur .= $next; $i++; } else { $inD = false; } }
            continue;
        }
        if ($inB) { $cur .= $ch; if ($ch === '`') { $inB = false; } continue; }
        if ($ch === '-' && $next === '-') { $inLine = true; $i++; continue; }
        if ($ch === '/' && $next === '*') { $inBlock = true; $i++; continue; }
        if ($ch === "'") { $inS = true; $cur .= $ch; continue; }
        if ($ch === '"') { $inD = true; $cur .= $ch; continue; }
        if ($ch === '`') { $inB = true; $cur .= $ch; continue; }
        if ($ch === ';') { $statements[] = trim($cur); $cur = ''; continue; }
        $cur .= $ch;
    }
    if (trim($cur) !== '') { $statements[] = trim($cur); }
    return array_values(array_filter($statements, static fn($s) => $s !== ''));
}

function install_exec_sql(PDO $pdo, string $sql, string $dbName): array {
    $errors = [];
    $statements = install_split_sql($sql);
    $ignored    = [1049, 1050, 1060, 1061, 1062, 1065];

    foreach ($statements as $stmt) {
        if ($stmt === '') { continue; }
        if (preg_match('/^USE\s+/i', $stmt)) {
            $stmt = 'USE `' . $dbName . '`';
        }
        try {
            $pdo->exec($stmt);
        } catch (PDOException $e) {
            $code = (int) ($e->errorInfo[1] ?? $e->getCode());
            if (!in_array($code, $ignored, true)) {
                $errors[] = 'Erreur SQL : ' . $e->getMessage() . ' — Statement : ' . substr($stmt, 0, 120);
            }
        }
    }
    return $errors;
}

function install_exec_sql_file(PDO $pdo, string $filePath, string $dbName): array {
    if (!file_exists($filePath)) {
        return ['Fichier introuvable : ' . basename($filePath)];
    }
    $sql = file_get_contents($filePath);
    if ($sql === false) {
        return ['Impossible de lire : ' . basename($filePath)];
    }
    return install_exec_sql($pdo, $sql, $dbName);
}

// ── Réinitialisation (réinstaller / mettre à jour) ─────────
if (isset($_GET['reset'])) {
    @unlink($flagFile);
    header('Location: install.php');
    exit;
}

// ── Déjà installé ? ─────────────────────────────────────────
$alreadyInstalled = install_is_done($flagFile);
if ($alreadyInstalled) {
    $checkPdo = null;
    if (defined('DB_HOST')) {
        $checkPdo = install_can_connect(DB_HOST, DB_USER, DB_PASS, (int) DB_PORT);
        if ($checkPdo && install_tables_exist($checkPdo, DB_NAME)) {
            $alreadyInstalled = true;
        } else {
            $alreadyInstalled = false;
        }
    }
}

// ── Valeurs par défaut du formulaire ────────────────────────
$formData = [
    'iam_name'          => 'IAM ACSI',
    'iam_base_url'      => install_detect_base_url(),
    'db_host'           => 'localhost',
    'db_user'           => 'root',
    'db_pass'           => '',
    'db_name'           => 'iam_local',
    'db_port'           => '3306',
    'admin_username'    => 'admin',
    'admin_email'       => 'admin@localhost',
    'admin_phone'       => '',
    'admin_first_name'  => 'Administrateur',
    'admin_last_name'   => 'Système',
    'admin_matricule'   => 'ADM-001',
    'admin_password'    => '',
    'with_demo'         => true,
];

// ── Traitement du formulaire ─────────────────────────────────
$step     = 'form';
$messages = [];

if ($_SERVER['REQUEST_METHOD'] === 'POST' && !$alreadyInstalled) {
    foreach ($formData as $key => $val) {
        if ($key === 'admin_password') {
            $formData[$key] = (string) ($_POST[$key] ?? '');
        } elseif ($key === 'with_demo') {
            $formData[$key] = isset($_POST['with_demo']);
        } else {
            $formData[$key] = trim((string) ($_POST[$key] ?? $val));
        }
    }

    $dbHost = $formData['db_host'];
    $dbUser = $formData['db_user'];
    $dbPass = $formData['db_pass'];
    $dbName = $formData['db_name'];
    $dbPort = (int) $formData['db_port'];
    $baseUrl = rtrim($formData['iam_base_url'], '/');
    $iamName = $formData['iam_name'];

    if ($iamName === '' || $baseUrl === '') {
        $messages[] = ['type' => 'danger', 'text' => 'Le nom de la plateforme et l\'URL de base sont obligatoires.'];
        $step = 'error';
    }

    if ($formData['admin_email'] === '' || filter_var($formData['admin_email'], FILTER_VALIDATE_EMAIL) === false) {
        $messages[] = ['type' => 'danger', 'text' => 'L\'adresse e-mail de l\'administrateur est invalide.'];
        $step = 'error';
    }

    if ($step !== 'error') {
        if ($formData['admin_password'] === '') {
            $formData['admin_password'] = install_generate_password();
        }
        if (strlen($formData['admin_password']) < 8) {
            $messages[] = ['type' => 'danger', 'text' => 'Le mot de passe administrateur doit faire au moins 8 caractères.'];
            $step = 'error';
        }
    }

    if ($step !== 'error') {
        $adminHash = password_hash($formData['admin_password'], PASSWORD_BCRYPT);

        $pdo = install_can_connect($dbHost, $dbUser, $dbPass, $dbPort);
        if (!$pdo) {
            $messages[] = ['type' => 'danger', 'text' => 'Impossible de se connecter au serveur MySQL. Vérifiez hôte, utilisateur et mot de passe.'];
            $step = 'error';
        }

        // 1. Créer la base
        if ($step !== 'error') {
            try {
                $pdo->exec('CREATE DATABASE IF NOT EXISTS `' . $dbName . '` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci');
                $pdo->exec('USE `' . $dbName . '`');
                $messages[] = ['type' => 'success', 'text' => 'Base de données « ' . esc($dbName) . ' » prête.'];
            } catch (PDOException $e) {
                $messages[] = ['type' => 'danger', 'text' => 'Erreur base de données : ' . $e->getMessage()];
                $step = 'error';
            }
        }

        // 2. Schéma
        if ($step !== 'error') {
            foreach (install_exec_sql_file($pdo, $schemaFile, $dbName) as $err) {
                $messages[] = ['type' => 'warning', 'text' => esc($err)];
            }
            $messages[] = ['type' => 'success', 'text' => 'Schéma de la base appliqué.'];
        }

        // 3. Données système + compte admin (placeholders)
        if ($step !== 'error') {
            $seed = file_get_contents($seedFile);
            if ($seed === false) {
                $messages[] = ['type' => 'danger', 'text' => 'Fichier sql/seed.sql introuvable.'];
                $step = 'error';
            } else {
                $seed = strtr($seed, [
                    '{{BASE_URL}}'           => $baseUrl,
                    '{{ADMIN_USERNAME}}'     => $formData['admin_username'] ?: 'admin',
                    '{{ADMIN_EMAIL}}'        => $formData['admin_email'],
                    '{{ADMIN_PHONE}}'        => $formData['admin_phone'],
                    '{{ADMIN_FIRST_NAME}}'   => $formData['admin_first_name'] ?: 'Administrateur',
                    '{{ADMIN_LAST_NAME}}'    => $formData['admin_last_name'] ?: 'Système',
                    '{{ADMIN_MATRICULE}}'    => $formData['admin_matricule'],
                    '{{ADMIN_PASSWORD_HASH}}'=> $adminHash,
                ]);
                foreach (install_exec_sql($pdo, $seed, $dbName) as $err) {
                    $messages[] = ['type' => 'warning', 'text' => esc($err)];
                }
                $messages[] = ['type' => 'success', 'text' => 'Données système et compte administrateur créés.'];
            }
        }

        // 4. Données de démonstration (optionnel)
        if ($step !== 'error' && $formData['with_demo']) {
            $demo = file_get_contents($demoFile);
            if ($demo === false) {
                $messages[] = ['type' => 'warning', 'text' => 'Fichier sql/seed-demo.sql introuvable (démo ignorée).'];
            } else {
                $demo = str_replace(['{{BASE_URL}}', '{{DEMO_PASSWORD_HASH}}'], [$baseUrl, $adminHash], $demo);
                foreach (install_exec_sql($pdo, $demo, $dbName) as $err) {
                    $messages[] = ['type' => 'warning', 'text' => esc($err)];
                }
                $messages[] = ['type' => 'success', 'text' => 'Données de démonstration importées.'];
            }
        }

        // 5. Réactualiser l'administrateur (réinstallation idempotente)
        if ($step !== 'error') {
            $stmt = $pdo->prepare('UPDATE users
                SET username=?, email=?, phone=?, password_hash=?, first_name=?, last_name=?, matricule=?, status=\'active\', must_change_password=0
                WHERE id = 1');
            $stmt->execute([
                $formData['admin_username'] ?: 'admin',
                $formData['admin_email'],
                $formData['admin_phone'],
                $adminHash,
                $formData['admin_first_name'] ?: 'Administrateur',
                $formData['admin_last_name'] ?: 'Système',
                $formData['admin_matricule'],
            ]);
            // Réactualiser les URLs des applications système après déplacement
            $stmt = $pdo->prepare('UPDATE applications SET url=? WHERE code=\'iam-admin\'');
            $stmt->execute([$baseUrl . '/admin']);

            // Rôles 100% locaux : garantir que l'app IAM possède le rôle
            // 'admin' (is_system) et que le compte administrateur (id 1) y
            // est attribué — c'est ce qui porte l'accès à la console.
            $pdo->exec("INSERT INTO roles (application_id, name, code, description, is_system)
                SELECT a.id, 'Administrateur', 'admin',
                       'Accès complet : CRUD sur l''application et administration de l''IAM', 1
                FROM applications a
                WHERE a.code = 'iam-admin'
                  AND NOT EXISTS (SELECT 1 FROM roles r WHERE r.code = 'admin' AND r.application_id = a.id)");
            $pdo->exec("INSERT IGNORE INTO user_roles (user_id, role_id, application_id)
                SELECT 1, r.id, a.id
                FROM roles r JOIN applications a ON a.id = r.application_id
                WHERE r.code = 'admin' AND (a.code = 'iam-admin' OR a.is_system = 1)
                  AND NOT EXISTS (SELECT 1 FROM user_roles ur
                                  WHERE ur.user_id = 1 AND ur.role_id = r.id
                                    AND ur.application_id = a.id)");
            if ($formData['with_demo']) {
                $stmt = $pdo->prepare('UPDATE applications SET url=?, redirect_uri=? WHERE code=\'gestion-presence\'');
                $stmt->execute([$baseUrl . '/GestionPresnceAdenIAM', $baseUrl . '/GestionPresnceAdenIAM/sso-login.php']);
                $stmt = $pdo->prepare('UPDATE applications SET url=?, redirect_uri=? WHERE code=\'gestion-salaire\'');
                $stmt->execute([$baseUrl . '/GestionSalaireAden', $baseUrl . '/GestionSalaireAden/sso-login.php']);
            }
        }

        // 6. Écrire config.php
        if ($step !== 'error') {
            $jwtSecret = bin2hex(random_bytes(32));
            $cfg  = "<?php\n";
            $cfg .= "// " . $iamName . " — Configuration centrale (auto-généré par l'installateur)\n";
            $cfg .= "define('IAM_BASE_URL',   '" . addslashes($baseUrl) . "');\n";
            $cfg .= "define('IAM_NAME',       '" . addslashes($iamName) . "');\n";
            $cfg .= "// Code de l'application IAM dont le rôle local 'admin' porte l'administration\n";
            $cfg .= "define('IAM_ADMIN_APP_CODE', 'iam-admin');\n";
            $cfg .= "define('IAM_VERSION',    '1.0.0');\n";
            $cfg .= "define('IAM_TAGLINE',    'Accès sécurisé aux applications');\n";
            $cfg .= "\n";
            $cfg .= "// Base de données\n";
            $cfg .= "define('DB_HOST',  '" . addslashes($dbHost) . "');\n";
            $cfg .= "define('DB_USER',  '" . addslashes($dbUser) . "');\n";
            $cfg .= "define('DB_PASS',  '" . addslashes($dbPass) . "');\n";
            $cfg .= "define('DB_NAME',  '" . addslashes($dbName) . "');\n";
            $cfg .= "define('DB_PORT',  '" . addslashes((string) $dbPort) . "');\n";
            $cfg .= "\n";
            $cfg .= "// Session PHP\n";
            $cfg .= "define('SESSION_LIFETIME',   3600);\n";
            $cfg .= "define('IDLE_TIMEOUT',       1800);\n";
            $cfg .= "define('SESSION_COOKIE_NAME','iam_session');\n";
            $cfg .= "\n";
            $cfg .= "// SSO\n";
            $cfg .= "define('SSO_TOKEN_LIFETIME', 60);\n";
            $cfg .= "\n";
            $cfg .= "// JWT\n";
            $cfg .= "define('IAM_JWT_SECRET',    '" . $jwtSecret . "');\n";
            $cfg .= "\n";
            $cfg .= "// MFA\n";
            $cfg .= "define('OTP_LENGTH',    6);\n";
            $cfg .= "define('OTP_LIFETIME',  300);\n";
            $cfg .= "define('OTP_MAX_TRIES', 5);\n";
            $cfg .= "\n";
            $cfg .= "// Anti force brute\n";
            $cfg .= "define('MAX_LOGIN_ATTEMPTS', 5);\n";
            $cfg .= "define('LOCKOUT_MINUTES',    30);\n";
            $cfg .= "\n";
            $cfg .= "// SMTP (optionnel pour MFA email)\n";
            $cfg .= "define('SMTP_HOST',  'smtp.gmail.com');\n";
            $cfg .= "define('SMTP_PORT',  465);\n";
            $cfg .= "define('SMTP_USER',  '');\n";
            $cfg .= "define('SMTP_PASS',  '');\n";
            $cfg .= "define('SMTP_FROM',  '');\n";
            $cfg .= "define('SMTP_FROM_NAME', '" . addslashes($iamName) . "');\n";
            $cfg .= "\n";
            $cfg .= "// Upload\n";
            $cfg .= "define('UPLOAD_DIR', __DIR__ . '/uploads/');\n";
            $cfg .= "define('MAX_UPLOAD_SIZE', 2 * 1024 * 1024);\n";

            if (!is_dir($configDir)) { mkdir($configDir, 0755, true); }
            @file_put_contents($configFile, $cfg);
            $messages[] = ['type' => 'success', 'text' => 'Fichier de configuration écrit.'];
        }

        // 7. Réécrire .htaccess avec le bon chemin de dossier
        if ($step !== 'error') {
            $base = install_detect_base_path($baseUrl);
            $ht  = "# ============================================================\n";
            $ht .= "# " . $iamName . " — Rewrite rules (régénéré par l'installateur, base: " . $base . ")\n";
            $ht .= "# ============================================================\n\n";
            $ht .= "RewriteEngine On\n\n";
            $ht .= "# ── Sécurité : cacher les fichiers sensibles ──────\n";
            $ht .= "RewriteRule ^\\.installed$ - [F,L]\n";
            $ht .= "RewriteRule ^\\.htaccess$ - [F,L]\n\n";
            $ht .= "# ── Rediriger vers install.php si pas encore installé ─\n";
            $ht .= "RewriteCond %{DOCUMENT_ROOT}" . $base . "/.installed !-f\n";
            $ht .= "RewriteCond %{REQUEST_URI} !" . $base . "/install\\.php\n";
            $ht .= "RewriteRule ^(.*)$ " . $base . "/install.php [R=302,L]\n\n";
            $ht .= "<IfModule mod_headers.c>\n";
            $ht .= "    Header set X-Content-Type-Options \"nosniff\"\n";
            $ht .= "    Header set X-Frame-Options \"SAMEORIGIN\"\n";
            $ht .= "    Header set X-XSS-Protection \"1; mode=block\"\n";
            $ht .= "    Header set Referrer-Policy \"strict-origin-when-cross-origin\"\n";
            $ht .= "</IfModule>\n\n";
            $ht .= "# ── Empêcher l'accès direct aux dossiers sensibles ─\n";
            $ht .= "<IfModule mod_rewrite.c>\n";
            $ht .= "    RewriteRule ^config/ - [F,L]\n";
            $ht .= "    RewriteRule ^includes/ - [F,L]\n";
            $ht .= "    RewriteRule ^sql/ - [F,L]\n";
            $ht .= "    RewriteRule ^client/ - [F,L]\n";
            $ht .= "</IfModule>\n\n";
            $ht .= "Options -Indexes\n";
            @file_put_contents($htaccessFile, $ht);
            $messages[] = ['type' => 'success', 'text' => 'Fichier .htaccess mis à jour.'];
        }

        // 8. Marquer installé
        if ($step !== 'error') {
            @mkdir($root . '/uploads', 0755, true);
            @file_put_contents($flagFile, date('Y-m-d H:i:s'));
            $messages[] = ['type' => 'success', 'text' => $iamName . ' a été installé avec succès !'];
            $step = 'success';
        }
    }
}
?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Installation — IAM-Local</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background: #f0f2f5; }
        .installer-card { max-width: 720px; margin: 40px auto; }
        .brand-logo { font-size: 2.2rem; font-weight: 700; color: #6f42c1; }
        .step-badge { display: inline-block; width: 32px; height: 32px; line-height: 32px; text-align: center; border-radius: 50%; background: #6f42c1; color: #fff; font-weight: 700; margin-right: 8px; }
    </style>
</head>
<body>
<div class="container">
    <div class="installer-card">
        <div class="card shadow">
            <div class="card-body p-4 p-md-5">
                <?php if ($alreadyInstalled && $_SERVER['REQUEST_METHOD'] !== 'POST'): ?>
                    <!-- ── DÉJÀ INSTALLÉ ─────────────────────── -->
                    <div class="text-center mb-4">
                        <div class="brand-logo"><?php echo esc($formData['iam_name']); ?></div>
                        <p class="text-muted">Déjà installé</p>
                    </div>
                    <div class="alert alert-info">
                        <strong>La plateforme est déjà installée.</strong> Vous pouvez réexécuter l'installation pour mettre à jour le schéma et les données (sans effet destructif).
                    </div>
                    <div class="d-grid gap-2">
                        <a href="<?php echo esc($formData['iam_base_url']); ?>/login.php" class="btn btn-primary btn-lg">Se connecter</a>
                        <a href="<?php echo esc($formData['iam_base_url']); ?>/admin/" class="btn btn-outline-secondary">Administration</a>
                        <a href="install.php?reset=1" class="btn btn-outline-danger" onclick="return confirm('Relancer l\'installation ? Le schéma et les données seront mis à jour.');">Réinstaller / mettre à jour</a>
                    </div>

                <?php elseif ($step === 'success'): ?>
                    <!-- ── SUCCÈS ────────────────────────────── -->
                    <div class="text-center mb-4">
                        <div class="brand-logo"><?php echo esc($formData['iam_name']); ?></div>
                        <p class="text-muted">Installation terminée</p>
                    </div>
                    <div class="text-center mb-3"><span style="font-size:3rem;">&#10003;</span></div>
                    <?php foreach ($messages as $msg): ?>
                        <div class="alert alert-<?php echo esc($msg['type']); ?>"><?php echo $msg['text']; ?></div>
                    <?php endforeach; ?>
                    <hr>
                    <h5 class="mb-3">Identifiants de l'administrateur</h5>
                    <table class="table table-bordered mb-4">
                        <tr><th>E-mail</th><td><code><?php echo esc($formData['admin_email']); ?></code></td></tr>
                        <tr><th>Mot de passe</th><td><code><?php echo esc($formData['admin_password']); ?></code></td></tr>
                    </table>
                    <p class="text-warning"><small>Vous devrez changer le mot de passe à la première connexion.</small></p>
                    <div class="d-grid gap-2">
                        <a href="<?php echo esc($formData['iam_base_url']); ?>/login.php" class="btn btn-primary btn-lg">Se connecter</a>
                        <a href="<?php echo esc($formData['iam_base_url']); ?>/admin/" class="btn btn-outline-secondary">Administration</a>
                    </div>

                <?php else: ?>
                    <!-- ── FORMULAIRE ────────────────────────── -->
                    <div class="text-center mb-4">
                        <div class="brand-logo">IAM ACSI</div>
                        <p class="text-muted">Assistant d'installation</p>
                    </div>

                    <?php if (!empty($messages)): ?>
                        <?php foreach ($messages as $msg): ?>
                            <div class="alert alert-<?php echo esc($msg['type']); ?>"><?php echo $msg['text']; ?></div>
                        <?php endforeach; ?>
                    <?php endif; ?>

                    <p class="mb-3">
                        <span class="step-badge">1</span>
                        Personnalisez la plateforme puis configurez votre serveur MySQL. La base sera créée automatiquement.
                    </p>

                    <form method="POST" action="">
                        <div class="card-title mb-2">Plateforme</div>
                        <div class="row g-3 mb-3">
                            <div class="col-md-6">
                                <label class="form-label">Nom de la plateforme</label>
                                <input type="text" class="form-control" name="iam_name" value="<?php echo esc($formData['iam_name']); ?>" required>
                            </div>
                            <div class="col-md-6">
                                <label class="form-label">URL de base</label>
                                <input type="text" class="form-control" name="iam_base_url" value="<?php echo esc($formData['iam_base_url']); ?>" required>
                                <div class="form-text">Auto-détectée, modifiable.</div>
                            </div>
                        </div>

                        <div class="card-title mb-2">Base de données MySQL</div>
                        <div class="row g-3 mb-3">
                            <div class="col-md-6">
                                <label class="form-label">Hôte</label>
                                <input type="text" class="form-control" name="db_host" value="<?php echo esc($formData['db_host']); ?>" required>
                            </div>
                            <div class="col-md-3">
                                <label class="form-label">Port</label>
                                <input type="number" class="form-control" name="db_port" value="<?php echo esc($formData['db_port']); ?>" required>
                            </div>
                            <div class="col-md-3">
                                <label class="form-label">Utilisateur</label>
                                <input type="text" class="form-control" name="db_user" value="<?php echo esc($formData['db_user']); ?>" required>
                            </div>
                            <div class="col-md-6">
                                <label class="form-label">Mot de passe</label>
                                <input type="password" class="form-control" name="db_pass" value="">
                                <div class="form-text">Laissez vide si aucun mot de passe.</div>
                            </div>
                            <div class="col-md-6">
                                <label class="form-label">Nom de la base</label>
                                <input type="text" class="form-control" name="db_name" value="<?php echo esc($formData['db_name']); ?>" required>
                                <div class="form-text">Sera créée si elle n'existe pas.</div>
                            </div>
                        </div>

                        <div class="card-title mb-2">Compte administrateur</div>
                        <div class="row g-3 mb-3">
                            <div class="col-md-6">
                                <label class="form-label">Nom</label>
                                <input type="text" class="form-control" name="admin_first_name" value="<?php echo esc($formData['admin_first_name']); ?>">
                            </div>
                            <div class="col-md-6">
                                <label class="form-label">Prénom</label>
                                <input type="text" class="form-control" name="admin_last_name" value="<?php echo esc($formData['admin_last_name']); ?>">
                            </div>
                            <div class="col-md-4">
                                <label class="form-label">Identifiant</label>
                                <input type="text" class="form-control" name="admin_username" value="<?php echo esc($formData['admin_username']); ?>">
                            </div>
                            <div class="col-md-4">
                                <label class="form-label">E-mail</label>
                                <input type="email" class="form-control" name="admin_email" value="<?php echo esc($formData['admin_email']); ?>" required>
                            </div>
                            <div class="col-md-4">
                                <label class="form-label">Matricule</label>
                                <input type="text" class="form-control" name="admin_matricule" value="<?php echo esc($formData['admin_matricule']); ?>">
                            </div>
                            <div class="col-md-8">
                                <label class="form-label">Mot de passe</label>
                                <input type="text" class="form-control" name="admin_password" value="<?php echo esc($formData['admin_password']); ?>" placeholder="Laisser vide pour générer automatiquement">
                                <div class="form-text">Minimum 8 caractères avec majuscule, minuscule, chiffre et caractère spécial.</div>
                            </div>
                            <div class="col-md-4 d-flex align-items-end mb-2">
                                <div class="form-check form-switch">
                                    <input class="form-check-input" type="checkbox" name="with_demo" id="with_demo" <?php echo $formData['with_demo'] ? 'checked' : ''; ?>>
                                    <label class="form-check-label" for="with_demo">Données de démonstration (ADEN, Présences/Salaires)</label>
                                </div>
                            </div>
                        </div>

                        <div class="d-grid">
                            <button type="submit" class="btn btn-primary btn-lg">Installer</button>
                        </div>
                    </form>
                <?php endif; ?>
            </div>
        </div>
        <p class="text-center text-muted mt-3 small">IAM ACSI v1.0.0 &mdash; Plateforme Identity &amp; Access Management</p>
    </div>
</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>