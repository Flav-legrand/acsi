<?php
/**
 * IAM-Local — Outils communs aux tests (ligne de commande uniquement).
 *
 *   - IamTestBrowser   : navigateur minimal cURL + cookies ;
 *   - IamTestFixtures  : application, rôle, client OAuth confidentiel et
 *                        comptes TEMPORAIRES, supprimés en fin de test ;
 *   - iam_test_authorize() : déroule /oauth.php (login → MFA →
 *                        consentement) jusqu'au retour vers redirect_uri ;
 *   - iam_test_token() : POST sur /api/oauth/token.php.
 *
 * Aucune donnée existante n'est modifiée : tout ce qui est créé porte le
 * préfixe « zz-test- » et est supprimé par IamTestFixtures::cleanup().
 */

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

require_once __DIR__ . '/../../includes/functions.php';
require_once __DIR__ . '/../../includes/oauth.php';

$GLOBALS['iam_test_failures'] = 0;

function iam_test_ok(bool $cond, string $label): bool
{
    $GLOBALS['iam_test_failures'] += $cond ? 0 : 1;
    echo ($cond ? "  [OK]   " : "  [ÉCHEC] ") . $label . "\n";
    return $cond;
}

final class IamTestBrowser
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
        if (strpos($location, '/') === 0) return $origin . $location;
        $dir = preg_replace('#/[^/]*$#', '/', $p['path'] ?? '/');
        return $origin . $dir . $location;
    }

    /** Champs du premier formulaire POST ; $approve choisit le bouton du consentement. */
    public static function formFields(string $html, ?string $approve = null): array
    {
        if (strpos($html, '<form') === false) return [];
        $dom = new DOMDocument();
        @$dom->loadHTML('<?xml encoding="UTF-8">' . $html);
        $xp = new DOMXPath($dom);
        foreach ($xp->query('//form[translate(@method,"post","POST")="POST"]') as $form) {
            $fields = [];
            foreach ($xp->query('.//input[@name]', $form) as $in) {
                $fields[$in->getAttribute('name')] = $in->getAttribute('value');
            }
            if ($approve === null || !isset($fields['approve']) || $fields['approve'] === $approve) {
                return $fields;
            }
        }
        return [];
    }
}

/**
 * Déroule l'autorisation OAuth jusqu'à la redirection vers $redirectUri
 * (non suivie) ou jusqu'à une page sans formulaire (ex. accès refusé).
 *
 * @return array{status:int, location:string, body:string, url:string}
 */
function iam_test_authorize(IamTestBrowser $b, string $authorizeUrl, string $redirectUri, array $account, string $password, string $approve = '1'): array
{
    $url = $authorizeUrl; $method = 'GET'; $form = [];
    for ($i = 0; $i < 20; $i++) {
        [$status, $body, $location] = $b->request($method, $url, $form);
        if ($status >= 300 && $status < 400 && $location !== '') {
            $next = IamTestBrowser::resolve($url, $location);
            if (strpos($next, $redirectUri) === 0) {
                return ['status' => $status, 'location' => $next, 'body' => $body, 'url' => $url];
            }
            $url = $next; $method = 'GET'; $form = [];
            continue;
        }
        $fields = IamTestBrowser::formFields($body, $approve);
        if (isset($fields['identifier'])) {
            $fields['identifier'] = $account['email'];
            $fields['password'] = $password;
        } elseif (isset($fields['code'])) {
            // MFA : code connu généré par la même fonction que mfa.php
            $fields['code'] = iam_generate_otp((int) $account['id'], 'email');
        } elseif (!isset($fields['approve'])) {
            return ['status' => $status, 'location' => '', 'body' => $body, 'url' => $url];
        }
        $method = 'POST'; $form = $fields;
    }
    throw new RuntimeException('trop de redirections');
}

/** Paramètres d'une URL de retour (code, error, state…). */
function iam_test_query(string $url): array
{
    parse_str((string) parse_url($url, PHP_URL_QUERY), $q);
    return $q;
}

/** @return array{0:int,1:array} statut HTTP et corps JSON décodé */
function iam_test_token(array $form, array $headers = []): array
{
    $b = new IamTestBrowser();
    [$status, $body] = $b->request('POST', IAM_BASE_URL . '/api/oauth/token.php', $form, $headers);
    $json = json_decode($body, true);
    return [$status, is_array($json) ? $json : ['raw' => mb_substr($body, 0, 300)]];
}

final class IamTestFixtures
{
    public const REDIRECT_URI = 'http://127.0.0.1:65530/callback';

    private string $tag;
    private array $appIds = [];
    private array $clientIds = [];
    private array $userIds = [];

    public function __construct()
    {
        $this->tag = 'zz-test-' . bin2hex(random_bytes(3));
    }

    public function tag(): string
    {
        return $this->tag;
    }

    /** Application + rôle « agent » appartenant à l'application. */
    public function application(string $suffix): array
    {
        $db = db();
        $code = "{$this->tag}-$suffix";
        $db->prepare('INSERT INTO applications (code, name, url, active, sso_prompt) VALUES (?, ?, ?, 1, 0)')
           ->execute([$code, "Test $code", 'http://127.0.0.1:65530']);
        $appId = (int) $db->lastInsertId();
        $this->appIds[] = $appId;
        $db->prepare('INSERT INTO roles (application_id, name, code) VALUES (?, ?, ?)')
           ->execute([$appId, 'Agent', 'agent']);
        return ['id' => $appId, 'code' => $code, 'role_id' => (int) $db->lastInsertId()];
    }

    /** Client confidentiel lié à l'application ; renvoie aussi le secret en clair. */
    public function client(array $app, bool $public = false): array
    {
        $db = db();
        $clientId = "{$this->tag}-{$app['code']}-client";
        $secret = $public ? null : bin2hex(random_bytes(16));
        $db->prepare('INSERT INTO oauth_clients
            (application_id, name, slug, platform, client_type, client_id, client_secret, redirect_uris, scopes, grant_types,
             base_url, is_active, refresh_enabled, pkce_required)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 1, ?)')
           ->execute([
               $app['id'], "Client {$app['code']}", $clientId, 'laravel', $public ? 'public' : 'confidential',
               $clientId, $secret !== null ? password_hash($secret, PASSWORD_DEFAULT) : null,
               json_encode([self::REDIRECT_URI]),
               json_encode(['openid', 'profile', 'email', 'roles', 'offline_access']),
               json_encode(['authorization_code', 'refresh_token']),
               'http://127.0.0.1:65530', $public ? 1 : 0,
           ]);
        $this->clientIds[] = $clientId;
        return ['client_id' => $clientId, 'secret' => $secret, 'public' => $public];
    }

    /** Compte actif, sans MFA personnelle ni changement de mot de passe imposé. */
    public function user(string $suffix, string $password, ?array $roleOn = null): array
    {
        $db = db();
        $username = "{$this->tag}-$suffix";
        $email = "$username@test.invalid";
        $db->prepare('INSERT INTO users (username, email, password_hash, first_name, last_name, status, mfa_enabled, must_change_password)
                      VALUES (?, ?, ?, ?, ?, ?, 0, 0)')
           ->execute([$username, $email, iam_hash_password($password), 'Test', $suffix, 'active']);
        $uid = (int) $db->lastInsertId();
        $this->userIds[] = $uid;
        if ($roleOn !== null) {
            $db->prepare('INSERT INTO user_roles (user_id, role_id, application_id) VALUES (?, ?, ?)')
               ->execute([$uid, $roleOn['role_id'], $roleOn['id']]);
        }
        return ['id' => $uid, 'email' => $email];
    }

    public function cleanup(): void
    {
        $db = db();
        foreach ($this->clientIds as $cid) {
            $db->prepare('DELETE FROM oauth_codes WHERE client_id = ?')->execute([$cid]);
            $db->prepare('DELETE FROM refresh_tokens WHERE client_id = ?')->execute([$cid]);
            $db->prepare('DELETE FROM oauth_client_events WHERE client_id = ?')->execute([$cid]);
            $db->prepare('DELETE FROM oauth_clients WHERE client_id = ?')->execute([$cid]);
        }
        foreach ($this->userIds as $uid) {
            $db->prepare('DELETE FROM users WHERE id = ?')->execute([$uid]);
        }
        foreach ($this->appIds as $aid) {
            $db->prepare('DELETE FROM applications WHERE id = ?')->execute([$aid]);
        }
        $this->clientIds = $this->userIds = $this->appIds = [];
    }

    public function __destruct()
    {
        $this->cleanup();
    }
}

/** URL d'autorisation (avec PKCE S256) ; renvoie [url, code_verifier]. */
function iam_test_authorize_url(string $clientId, string $state, string $redirectUri = IamTestFixtures::REDIRECT_URI, string $scope = 'openid profile email roles offline_access'): array
{
    $verifier = base64_url_encode(random_bytes(32));
    $challenge = base64_url_encode(hash('sha256', $verifier, true));
    $url = IAM_BASE_URL . '/oauth.php?' . http_build_query([
        'response_type' => 'code',
        'client_id' => $clientId,
        'redirect_uri' => $redirectUri,
        'scope' => $scope,
        'state' => $state,
        'code_challenge' => $challenge,
        'code_challenge_method' => 'S256',
    ]);
    return [$url, $verifier];
}
