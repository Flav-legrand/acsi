<?php
// IAM-Local — Chargement de config/config.php + contrôle d'intégrité.
// Inclus par includes/db.php, includes/functions.php et includes/mailer.php
// à la place d'un require direct de config.php.

require_once __DIR__ . '/config_constants.php';

if (!function_exists('iam_check_config_integrity')) {

/**
 * Liste des problèmes de configuration (vide si tout va bien) :
 * constantes absentes, et constantes critiques présentes mais vides.
 */
function iam_config_problems(): array
{
    $problems = [];
    foreach (iam_required_config_constants() as $name) {
        if (!defined($name)) $problems[] = "$name : constante absente";
    }
    foreach (['IAM_BASE_URL', 'DB_HOST', 'DB_NAME', 'IAM_JWT_SECRET'] as $name) {
        if (defined($name) && trim((string) constant($name)) === '') {
            $problems[] = "$name : valeur vide" . ($name === 'IAM_JWT_SECRET' || strpos($name, 'DB_') === 0 ? ' (config/config.local.php absent ?)' : '');
        }
    }
    return $problems;
}

/** Arrête la requête avec un message clair si la configuration est incomplète. */
function iam_check_config_integrity(?array $problems = null): void
{
    $problems = $problems ?? iam_config_problems();
    if ($problems === []) return;

    if (PHP_SAPI === 'cli') {
        fwrite(STDERR, "Configuration IAM incomplète (config/config.php) :\n  - " . implode("\n  - ", $problems)
            . "\nRéférence : config/config.template.php. Voir docs/installation.md.\n");
        exit(1);
    }

    // Lien vers install.php, calculé sans dépendre d'IAM_BASE_URL (peut manquer)
    $rootDir = str_replace('\\', '/', dirname(__DIR__));
    $docRoot = rtrim(str_replace('\\', '/', (string) ($_SERVER['DOCUMENT_ROOT'] ?? '')), '/');
    $basePath = ($docRoot !== '' && stripos($rootDir, $docRoot) === 0) ? substr($rootDir, strlen($docRoot)) : '';
    $installUrl = $basePath . '/install.php';

    http_response_code(500);
    $isApi = strpos((string) ($_SERVER['SCRIPT_NAME'] ?? ''), '/api/') !== false;
    if ($isApi) {
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(['error' => 'server_misconfigured', 'error_description' => 'Configuration IAM incomplète.', 'missing' => $problems], JSON_UNESCAPED_UNICODE);
        exit;
    }
    header('Content-Type: text/html; charset=utf-8');
    $items = '';
    foreach ($problems as $p) $items .= '<li><code>' . htmlspecialchars($p) . '</code></li>';
    echo '<!DOCTYPE html><html lang="fr"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">'
       . '<title>Configuration incomplète</title>'
       . '<style>body{font-family:system-ui,sans-serif;background:#f4f6fa;color:#1f2937;margin:0;padding:40px 16px}'
       . '.card{max-width:640px;margin:0 auto;background:#fff;border:1px solid #e5e7eb;border-radius:10px;padding:28px}'
       . 'h1{font-size:20px;margin:0 0 12px;color:#b91c1c}code{background:#f3f4f6;padding:1px 5px;border-radius:4px}'
       . 'a.btn{display:inline-block;margin-top:16px;background:#1d4ed8;color:#fff;padding:10px 16px;border-radius:6px;text-decoration:none}</style></head><body>'
       . '<div class="card"><h1>Configuration de l\'IAM incomplète</h1>'
       . '<p>Le fichier <code>config/config.php</code> ne définit pas tout ce dont l\'IAM a besoin. Problèmes détectés :</p><ul>' . $items . '</ul>'
       . '<p>Pour corriger :</p><ol>'
       . '<li>relancer l\'installateur (supprimer d\'abord le fichier <code>.installed</code> à la racine), qui réécrit une configuration complète ;</li>'
       . '<li>ou compléter <code>config/config.php</code> à partir de <code>config/config.template.php</code>, et les secrets dans <code>config/config.local.php</code>.</li>'
       . '</ol><p>Détails : <code>docs/installation.md</code>.</p>'
       . '<a class="btn" href="' . htmlspecialchars($installUrl) . '">Ouvrir install.php</a></div></body></html>';
    exit;
}

} // fin if !function_exists

$iamConfigFile = __DIR__ . '/../config/config.php';
if (!is_file($iamConfigFile)) {
    iam_check_config_integrity(['config/config.php : fichier absent (installation non effectuée)']);
}
require_once $iamConfigFile;
iam_check_config_integrity();
