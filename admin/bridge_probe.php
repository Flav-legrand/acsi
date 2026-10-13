<?php
// IAM-Local — Détection de la structure d'une base applicative pour configurer
// graphiquement le « Pont de session locale » (Admin → Applications).
require_once __DIR__ . '/_guard.php';

header('Content-Type: application/json; charset=utf-8');
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode(['ok' => false, 'error' => 'Requête POST requise.']);
    exit;
}
if (!hash_equals($_SESSION['csrf_token'], (string) ($_POST['csrf'] ?? ''))) {
    echo json_encode(['ok' => false, 'error' => 'Jeton CSRF invalide.']);
    exit;
}

$ident  = static function (string $s, int $max = 64): string {
    return substr(preg_replace('/[^A-Za-z0-9_\-. ]+/', '', $s), 0, $max);
};
$host    = $ident($_POST['db_host'] ?? 'localhost', 120);
$port    = (int) ($_POST['db_port'] ?? 3306);
$dbName  = $ident($_POST['db_name'] ?? '', 64);
$dbUser  = $ident($_POST['db_user'] ?? 'root', 64);
$dbPass  = (string) ($_POST['db_pass'] ?? '');
$table   = $ident($_POST['table'] ?? '', 64);
$matchIam = in_array($_POST['match_iam'] ?? 'username', ['username', 'email', 'matricule'], true) ? $_POST['match_iam'] : 'username';
$matchLocal   = $ident($_POST['match_local'] ?? '', 64);
$keyRole      = $ident($_POST['key_role'] ?? '', 64);
$keyStatusCol = $ident($_POST['create_status_col'] ?? '', 64);

$allowedHosts = ['localhost', '127.0.0.1', '::1'];
if (!in_array(strtolower(trim($host)), $allowedHosts, true)) {
    echo json_encode(['ok' => false, 'error' => 'Hôte refusé : détection locale uniquement.']);
    exit;
}

try {
    $dsn = 'mysql:host=' . $host . ';port=' . $port . ';charset=utf8mb4';
    if ($dbName !== '') {
        $dsn .= ';dbname=' . $dbName;
    }
    $pdo = new PDO($dsn, $dbUser, $dbPass, [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_TIMEOUT            => 4,
    ]);

    $out = ['ok' => true, 'connected' => $dbName !== '' ? $dbName : (string) $pdo->query('SELECT DATABASE()')->fetchColumn()];

    // Bases disponibles (utile pour pré-remplir le champ « Base »)
    $out['databases'] = [];
    foreach ($pdo->query('SHOW DATABASES') as $row) {
        $name = (string) (array_values($row)[0]);
        if (!in_array(strtolower($name), ['information_schema', 'mysql', 'performance_schema', 'sys'], true)) {
            $out['databases'][] = $name;
        }
    }
    sort($out['databases']);

    // Tables de la base
    $out['tables'] = [];
    if ($dbName !== '') {
        foreach ($pdo->query('SHOW TABLES') as $row) {
            $out['tables'][] = (string) (array_values($row)[0]);
        }
        sort($out['tables']);
        $out['tables'] = array_values($out['tables']);
    }

    // Colonnes + volumes + valeurs utiles de la table
    $out['columns'] = [];
    if ($dbName !== '' && $table !== '') {
        $st = $pdo->prepare("SELECT COLUMN_NAME, DATA_TYPE FROM information_schema.columns
            WHERE table_schema = ? AND table_name = ? ORDER BY ordinal_position");
        $st->execute([$dbName, $table]);
        $cols = $st->fetchAll();
        $out['columns'] = array_values(array_map(static fn($c) => $c['COLUMN_NAME'], $cols));
        if ($out['columns']) {
            $out['count'] = (int) $pdo->query('SELECT COUNT(*) FROM `' . $table . '`')->fetchColumn();
            foreach ([
                ['key' => 'match_local', 'col' => $matchLocal],
                ['key' => 'key_role',    'col' => $keyRole],
                ['key' => 'key_status_col', 'col' => $keyStatusCol],
            ] as $probe) {
                $col = $probe['col'];
                if ($col === '' || !in_array($col, $out['columns'], true)) {
                    continue;
                }
                $stV = $pdo->query('SELECT DISTINCT `' . $col . '` FROM `' . $table . '` WHERE `' . $col . '` IS NOT NULL LIMIT 50');
                $vals = array_values(array_map(static fn($v) => (string) $v, $stV->fetchAll(PDO::FETCH_COLUMN)));
                $out[$probe['key'] . '_values'] = array_values(array_filter($vals, static fn($v) => $v !== ''));
            }
        }
    }

    // Compatibilité : quels utilisateurs IAM actifs seront reconnus dans la colonne locale
    $out['match_coverage'] = [];
    if ($dbName !== '' && $table !== '' && $matchLocal !== '') {
        $iam = db();
        $needleField = $matchIam;
        $stU = $iam->prepare('SELECT username, email, IFNULL(matricule, "") AS matricule, first_name, last_name, status FROM users WHERE status = ? ORDER BY username LIMIT 80');
        $stU->execute(['active']);
        $stF = $pdo->prepare('SELECT COUNT(*) FROM `' . $table . '` WHERE `' . $matchLocal . '` = ?');
        foreach ($stU->fetchAll() as $u) {
            $needle = (string) ($u[$needleField] ?? '');
            $found = false;
            if ($needle !== '') {
                $stF->execute([$needle]);
                $found = (int) $stF->fetchColumn() > 0;
            }
            $out['match_coverage'][] = [
                'user'   => $u['username'],
                'name'   => trim($u['first_name'] . ' ' . $u['last_name']),
                'needle' => $needle,
                'found'  => $found,
            ];
        }
    }

    echo json_encode($out, JSON_UNESCAPED_UNICODE);
} catch (\Throwable $e) {
    echo json_encode(['ok' => false, 'error' => $e->getMessage()]);
}
exit;