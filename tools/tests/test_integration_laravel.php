<?php
/**
 * IAM-Local — Test d'intégration d'une application Laravel (SSO + OIDC)
 *
 * Vérifie, depuis l'IAM, qu'une application Laravel générée par
 * tools/generateur-app (pile laravel) reçoit bien les bons rôles et les
 * bonnes permissions, pour CHAQUE compte de test et par les DEUX voies :
 *
 *   1. configuration en base : application, client OIDC (confidentiel,
 *      PKCE obligatoire, redirect_uri), permissions, rôles, matrice,
 *      comptes de test ;
 *   2. connexion complète simulée (navigateur) : /login/<voie> →
 *      formulaire IAM → MFA → consentement → callback Laravel ;
 *      le code MFA est généré directement en base (iam_generate_otp),
 *      le test est donc entièrement automatique, SMTP configuré ou non ;
 *   3. comparaison de /iam/me (côté Laravel) avec les droits calculés
 *      par l'IAM lui-même (mêmes fonctions que validate.php et OIDC) ;
 *   4. déconnexion.
 *
 * Usage (ligne de commande UNIQUEMENT, depuis la racine de l'IAM) :
 *
 *   php tools/tests/test_integration_laravel.php --app=partenaires --password=<mdp démo>
 *   php tools/tests/test_integration_laravel.php --app=stages-emplois --password=... --modes=oidc
 *   php tools/tests/test_integration_laravel.php --app=partenaires --password=... --app-url=http://localhost:8001
 *
 * Prérequis : l'application Laravel tourne (php artisan serve --port=…)
 * avec APP_ENV=local (route de diagnostic /iam/me).
 *
 * Code de sortie : 0 si tout est conforme, 1 sinon.
 */

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

require_once __DIR__ . '/../../includes/functions.php';
require_once __DIR__ . '/../../includes/oauth.php';

$opts = getopt('', ['app:', 'password:', 'app-url::', 'modes::', 'user::']);
$appCode  = (string) ($opts['app'] ?? '');
$password = (string) ($opts['password'] ?? '');
$modes    = array_filter(explode(',', (string) ($opts['modes'] ?? 'oidc,sso')));
$onlyUser = (string) ($opts['user'] ?? '');

if ($appCode === '' || $password === '') {
    fwrite(STDERR, "Usage : php tools/tests/test_integration_laravel.php --app=<code> --password=<mot de passe des comptes de test> [--app-url=URL] [--modes=oidc,sso] [--user=email]\n");
    exit(2);
}

$failures = 0;
function ok(bool $cond, string $label): void
{
    global $failures;
    $failures += $cond ? 0 : 1;
    echo ($cond ? "  [OK]   " : "  [ÉCHEC] ") . $label . "\n";
}

$db = db();

/* ================================================================
   1. CONFIGURATION EN BASE
   ================================================================ */
echo "== Configuration de « $appCode » dans l'IAM\n";
$st = $db->prepare('SELECT * FROM applications WHERE code = ?');
$st->execute([$appCode]);
$app = $st->fetch();
if (!$app) {
    fwrite(STDERR, "Application « $appCode » introuvable. Importez d'abord sql/seed-app-$appCode.sql.\n");
    exit(1);
}
$appUrl = rtrim((string) ($opts['app-url'] ?? $app['url']), '/');
ok((int) $app['active'] === 1, "Application active ($appUrl)");

$st = $db->prepare('SELECT * FROM oauth_clients WHERE application_id = ? ORDER BY is_active DESC, id LIMIT 1');
$st->execute([(int) $app['id']]);
$client = $st->fetch();
ok((bool) $client, 'Client OIDC lié à l\'application' . ($client ? " ({$client['client_id']})" : ''));
if ($client) {
    $redirects = json_decode((string) $client['redirect_uris'], true) ?: [];
    $logoutUris = json_decode((string) $client['post_logout_uris'], true) ?: [];
    $scopes = json_decode((string) $client['scopes'], true) ?: [];
    ok((int) $client['is_active'] === 1, 'Client OIDC actif');
    ok($client['client_type'] === 'confidential', 'Client confidentiel (secret côté serveur Laravel)');
    ok((int) $client['pkce_required'] === 1, 'PKCE S256 obligatoire');
    ok(in_array("$appUrl/callback", $redirects, true), "redirect_uri $appUrl/callback enregistrée");
    ok(in_array("$appUrl/logged-out", $logoutUris, true), "post_logout_uri $appUrl/logged-out enregistrée");
    ok(!array_diff(['openid', 'profile', 'email', 'roles'], $scopes), 'Scopes openid profile email roles autorisés');
}

$nbPerms = (int) $db->query('SELECT COUNT(*) FROM permissions WHERE application_id = ' . (int) $app['id'])->fetchColumn();
ok($nbPerms > 0, "$nbPerms permissions déclarées");
$st = $db->prepare('SELECT r.code, COUNT(rp.permission_id) n FROM roles r LEFT JOIN role_permissions rp ON rp.role_id = r.id
                    WHERE r.application_id = ? GROUP BY r.id, r.code ORDER BY r.code');
$st->execute([(int) $app['id']]);
foreach ($st->fetchAll() as $r) {
    echo "         rôle {$r['code']} : {$r['n']} permission(s)\n";
}

$st = $db->prepare("SELECT DISTINCT u.id, u.email, u.status FROM users u JOIN user_roles ur ON ur.user_id = u.id
                    WHERE ur.application_id = ? AND u.email LIKE '%@acsi.local' ORDER BY u.email");
$st->execute([(int) $app['id']]);
$accounts = array_values(array_filter($st->fetchAll(), fn ($u) => $onlyUser === '' || strcasecmp($u['email'], $onlyUser) === 0));
ok($accounts !== [], count($accounts) . ' compte(s) de test');

/* ================================================================
   2. NAVIGATEUR MINIMAL (cURL + cookies)
   ================================================================ */
final class Browser
{
    private string $jar;

    public function __construct()
    {
        $this->jar = tempnam(sys_get_temp_dir(), 'iamtest');
    }

    public function __destruct()
    {
        @unlink($this->jar);
    }

    /** @return array{0:int,1:string,2:string} statut, corps, en-tête Location */
    public function request(string $method, string $url, array $form = [], array $headers = []): array
    {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER         => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_COOKIEJAR      => $this->jar,
            CURLOPT_COOKIEFILE     => $this->jar,
            CURLOPT_TIMEOUT        => 30,
            CURLOPT_USERAGENT      => 'iam-test-integration/1.0',
            CURLOPT_HTTPHEADER     => $headers,
        ]);
        if ($method === 'POST') {
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($form));
        }
        $raw = curl_exec($ch);
        if ($raw === false) {
            throw new RuntimeException("Requête impossible vers $url : " . curl_error($ch));
        }
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $headerSize = (int) curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        curl_close($ch);
        $head = substr($raw, 0, $headerSize);
        $location = preg_match('/^Location:\s*(.+)$/mi', $head, $m) ? trim($m[1]) : '';
        return [$status, substr($raw, $headerSize), $location];
    }

    public static function resolve(string $base, string $location): string
    {
        if (preg_match('#^https?://#i', $location)) return $location;
        $p = parse_url($base);
        $origin = $p['scheme'] . '://' . $p['host'] . (isset($p['port']) ? ':' . $p['port'] : '');
        if (str_starts_with($location, '/')) return $origin . $location;
        $dir = preg_replace('#/[^/]*$#', '/', $p['path'] ?? '/');
        return $origin . $dir . $location;
    }

    public static function formFields(string $html): array
    {
        if (!str_contains($html, '<form')) return [];
        $dom = new DOMDocument();
        @$dom->loadHTML('<?xml encoding="UTF-8">' . $html);
        $xp = new DOMXPath($dom);
        $form = $xp->query('//form[translate(@method,"post","POST")="POST"]')->item(0);
        if (!$form) return [];
        $fields = [];
        foreach ($xp->query('.//input[@name]', $form) as $in) {
            $fields[$in->getAttribute('name')] = $in->getAttribute('value');
        }
        return $fields;
    }
}

/**
 * Déroule la connexion jusqu'au retour dans l'application.
 * @return array{0:int,1:string} statut et URL finale
 */
function iam_test_login(Browser $b, string $start, string $appUrl, array $account, string $password): array
{
    $url = $start; $method = 'GET'; $form = [];
    for ($i = 0; $i < 30; $i++) {
        [$status, $body, $location] = $b->request($method, $url, $form);
        if ($status >= 300 && $status < 400 && $location !== '') {
            $url = Browser::resolve($url, $location); $method = 'GET'; $form = [];
            continue;
        }
        if ($i > 0 && str_starts_with($url, $appUrl)) {
            return [$status, $url];
        }
        $fields = Browser::formFields($body);
        if (isset($fields['identifier'])) {
            $fields['identifier'] = $account['email'];
            $fields['password'] = $password;
        } elseif (isset($fields['code'])) {
            // MFA : on remplace le code envoyé par un code connu (même fonction que mfa.php)
            $fields['code'] = iam_generate_otp((int) $account['id'], 'email');
        } elseif (isset($fields['approve'])) {
            $fields['approve'] = '1';
        } else {
            $msg = trim(preg_replace('/\s+/', ' ', strip_tags($body)));
            throw new RuntimeException("page inattendue (HTTP $status) sur $url : " . mb_substr($msg, 0, 160));
        }
        $method = 'POST'; $form = $fields;
    }
    throw new RuntimeException('trop de redirections');
}

/* ================================================================
   3. CONNEXIONS ET COMPARAISON DES DROITS
   ================================================================ */
foreach ($accounts as $account) {
    $uid = (int) $account['id'];
    $expectedRoles = array_column(iam_user_roles($uid, (int) $app['id']), 'code');
    // Vérité IAM : même calcul que les jetons OIDC et que validate.php
    $expectedPerms = $client
        ? iam_oauth_user_permissions($client, $uid)
        : array_column(iam_user_permissions($uid, (int) $app['id']), 'code');
    sort($expectedRoles);
    sort($expectedPerms);

    foreach ($modes as $mode) {
        echo "\n== {$account['email']} — voie " . strtoupper($mode) . "\n";
        $b = new Browser();
        try {
            [$status, $final] = iam_test_login($b, "$appUrl/login/$mode", $appUrl, $account, $password);
        } catch (RuntimeException $e) {
            ok(false, 'Connexion : ' . $e->getMessage());
            continue;
        }
        ok($status === 200, "Retour dans l'application : HTTP $status ($final)");

        [, $json] = $b->request('GET', "$appUrl/iam/me", [], ['Accept: application/json']);
        $me = json_decode($json, true);
        if (!is_array($me) || empty($me['user'])) {
            ok(false, '/iam/me ne renvoie pas de session (APP_ENV=local ?)');
            continue;
        }
        $gotRoles = $me['roles']; sort($gotRoles);
        $gotPerms = $me['permissions']; sort($gotPerms);
        ok($me['mode'] === $mode, "Session ouverte par la voie $mode");
        ok((int) $me['user']['id'] === $uid, "Identité : sub {$me['user']['id']} = users.id $uid");
        ok($gotRoles === $expectedRoles, 'Rôles : ' . implode(', ', $gotRoles) . ' (attendu : ' . implode(', ', $expectedRoles) . ')');
        $missing = array_diff($expectedPerms, $gotPerms);
        $extra = array_diff($gotPerms, $expectedPerms);
        ok(!$missing && !$extra, count($gotPerms) . ' permission(s) reçue(s), ' . count($expectedPerms) . ' attendue(s)'
            . ($missing ? ' — manquantes : ' . implode(', ', $missing) : '')
            . ($extra ? ' — en trop : ' . implode(', ', $extra) : ''));

        // Déconnexion
        [, $home] = $b->request('GET', "$appUrl/");
        if (preg_match('/name="_token" value="([^"]+)"/', $home, $m)) {
            [$s, , $loc] = $b->request('POST', "$appUrl/logout", ['_token' => $m[1]]);
            [, , $loc2] = $loc ? $b->request('GET', Browser::resolve("$appUrl/logout", $loc)) : [0, '', ''];
            ok(str_starts_with($loc2, "$appUrl/logged-out"), 'Déconnexion IAM puis retour sur /logged-out');
        }
    }
}

echo "\n" . ($failures === 0 ? "RÉSULTAT : tout est conforme.\n" : "RÉSULTAT : $failures anomalie(s).\n");
exit($failures === 0 ? 0 : 1);
