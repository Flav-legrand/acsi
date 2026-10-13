<?php
/**
 * IAM-Local — Tests de non-régression des correctifs de sécurité OAuth.
 *
 * Autonome : crée une application, un client confidentiel et des comptes
 * TEMPORAIRES (préfixe zz-test-), rejoue les flux en HTTP contre l'IAM
 * (IAM_BASE_URL), puis supprime tout. Aucune application cliente requise.
 *
 * Usage (depuis la racine de l'IAM, serveur web démarré) :
 *   php tools/tests/test_oauth_securite.php
 *
 * Code de sortie : 0 si tout est conforme, 1 sinon.
 */

require_once __DIR__ . '/lib_iam_test.php';

$fx = new IamTestFixtures();
$password = 'Zz!' . bin2hex(random_bytes(8));

$app      = $fx->application('app');
$client   = $fx->client($app);
$withRole = $fx->user('avec-role', $password, $app);
$noRole   = $fx->user('sans-role', $password);

/* ================================================================
   B. Rôle obligatoire avant émission du code d'autorisation
   ================================================================ */
echo "== B. Autorisation : rôle requis sur l'application ({$fx->tag()})\n";

// B1 — utilisateur sans rôle : écran « Accès refusé », aucun code émis
$state = bin2hex(random_bytes(8));
[$url] = iam_test_authorize_url($client['client_id'], $state);
$r = iam_test_authorize(new IamTestBrowser(), $url, IamTestFixtures::REDIRECT_URI, $noRole, $password);
iam_test_ok($r['status'] === 403, "Sans rôle : écran d'accès refusé (HTTP {$r['status']})");
$deny = preg_match('/id="oauth-access-denied" href="([^"]+)"/', $r['body'], $m) ? html_entity_decode($m[1]) : '';
$q = iam_test_query($deny);
iam_test_ok(($q['error'] ?? '') === 'access_denied' && ($q['state'] ?? '') === $state,
    'Sans rôle : lien de retour redirect_uri?error=access_denied&state=…');
$st = db()->prepare('SELECT COUNT(*) FROM oauth_codes WHERE client_id = ? AND user_id = ?');
$st->execute([$client['client_id'], $noRole['id']]);
iam_test_ok((int) $st->fetchColumn() === 0, 'Sans rôle : aucun code d’autorisation enregistré');
$st = db()->prepare("SELECT details FROM audit_logs WHERE action = 'oauth_authorize_denied' AND user_id = ? ORDER BY id DESC LIMIT 1");
$st->execute([$noRole['id']]);
$details = json_decode((string) $st->fetchColumn(), true) ?: [];
iam_test_ok(($details['raison'] ?? '') === 'no_role_on_application' && (int) ($details['application_id'] ?? 0) === $app['id'],
    'Sans rôle : audit oauth_authorize_denied (raison no_role_on_application)');

// B2 — POST forgé sur le consentement : redirection access_denied, pas de code
$b = new IamTestBrowser();
[, , $loc] = $b->request('GET', $url);                       // → login.php
[, $loginPage] = $b->request('GET', IamTestBrowser::resolve($url, $loc));
$csrf = preg_match('/name="csrf" value="([^"]+)"/', $loginPage, $m) ? $m[1] : '';
iam_test_authorize($b, $url, IamTestFixtures::REDIRECT_URI, $noRole, $password); // session ouverte
parse_str((string) parse_url($url, PHP_URL_QUERY), $params);
[$s, , $loc] = $b->request('POST', IAM_BASE_URL . '/oauth.php', $params + ['csrf' => $csrf, 'approve' => '1']);
$q = iam_test_query($loc);
iam_test_ok($s === 302 && ($q['error'] ?? '') === 'access_denied' && !isset($q['code']),
    'Sans rôle : consentement forgé → redirect_uri?error=access_denied');

// B3 — utilisateur avec rôle : code émis normalement
$state = bin2hex(random_bytes(8));
[$url, $verifier] = iam_test_authorize_url($client['client_id'], $state);
$r = iam_test_authorize(new IamTestBrowser(), $url, IamTestFixtures::REDIRECT_URI, $withRole, $password);
$q = iam_test_query($r['location']);
iam_test_ok(!empty($q['code']) && ($q['state'] ?? '') === $state, 'Avec rôle : code d’autorisation émis');

/* ================================================================
   C. Renouvellement : secret client, liaison au client, rotation
   ================================================================ */
echo "\n== C. Renouvellement (grant_type=refresh_token)\n";
$otherApp    = $fx->application('autre');
$otherClient = $fx->client($otherApp);
$auditReason = static function (int $userId): string {
    $st = db()->prepare("SELECT details FROM audit_logs WHERE action = 'oauth_refresh_failed' AND user_id = ? ORDER BY id DESC LIMIT 1");
    $st->execute([$userId]);
    return (string) ((json_decode((string) $st->fetchColumn(), true) ?: [])['raison'] ?? '');
};
$refresh = static function (string $token, string $clientId, ?string $secret, bool $basic = false): array {
    $form = ['grant_type' => 'refresh_token', 'refresh_token' => $token];
    $headers = [];
    if ($basic) {
        $headers[] = 'Authorization: Basic ' . base64_encode("$clientId:$secret");
    } elseif ($clientId !== '') {
        $form += ['client_id' => $clientId] + ($secret !== null ? ['client_secret' => $secret] : []);
    }
    return iam_test_token($form, $headers);
};

[$s, $tok] = iam_test_token([
    'grant_type' => 'authorization_code', 'code' => $q['code'] ?? '', 'redirect_uri' => IamTestFixtures::REDIRECT_URI,
    'code_verifier' => $verifier, 'client_id' => $client['client_id'], 'client_secret' => $client['secret'],
]);
$t1 = (string) ($tok['refresh_token'] ?? '');
if (!iam_test_ok($s === 200 && $t1 !== '', "Échange du code : refresh_token obtenu (HTTP $s)")) {
    echo '         ' . json_encode($tok, JSON_UNESCAPED_UNICODE) . "\n";
}

[$s, $r] = $refresh($t1, $client['client_id'], 'mauvais-secret');
iam_test_ok($s === 401 && ($r['error'] ?? '') === 'invalid_client', "Mauvais secret → 401 invalid_client (HTTP $s)");
$st = db()->prepare("SELECT details FROM audit_logs WHERE action = 'oauth_refresh_failed' ORDER BY id DESC LIMIT 1");
$st->execute();
$last = json_decode((string) $st->fetchColumn(), true) ?: [];
iam_test_ok(($last['raison'] ?? '') === 'invalid_client_secret' && ($last['client_id'] ?? '') === $client['client_id'],
    'Audit oauth_refresh_failed : raison invalid_client_secret');

[$s, $r] = $refresh($t1, $client['client_id'], null);
iam_test_ok($s === 401 && ($r['error'] ?? '') === 'invalid_client', "Client confidentiel sans secret → 401 invalid_client (HTTP $s)");

[$s, $r] = $refresh($t1, '', null);
iam_test_ok($s === 401 && ($r['error'] ?? '') === 'invalid_client', "Sans aucune identification du client → 401 invalid_client (HTTP $s)");

[$s, $r] = $refresh($t1, $otherClient['client_id'], $otherClient['secret']);
iam_test_ok($s === 400 && ($r['error'] ?? '') === 'invalid_grant', "client_id d'une autre application → 400 invalid_grant (HTTP $s)");
iam_test_ok($auditReason($withRole['id']) === 'client_mismatch', 'Audit oauth_refresh_failed : raison client_mismatch');

[$s, $r] = $refresh($t1, $client['client_id'], $client['secret']);
$t2 = (string) ($r['refresh_token'] ?? '');
iam_test_ok($s === 200 && !empty($r['access_token']) && $t2 !== '' && $t2 !== $t1,
    "Bon secret (corps POST) → 200, nouvel access_token et nouveau refresh_token (HTTP $s)");

[$s, $r] = $refresh($t2, $client['client_id'], $client['secret'], true);
$t3 = (string) ($r['refresh_token'] ?? '');
iam_test_ok($s === 200 && $t3 !== '' && $t3 !== $t2, "Bon secret (Authorization: Basic) → 200, rotation (HTTP $s)");

// Le refresh du SSO maison (/api/refresh.php, sans client) ne doit pas
// accepter un refresh_token OAuth : ce serait un contournement.
$ch = curl_init(IAM_BASE_URL . '/api/refresh.php');
curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_POST => true,
    CURLOPT_HTTPHEADER => ['Content-Type: application/json'], CURLOPT_POSTFIELDS => json_encode(['refresh_token' => $t3])]);
curl_exec($ch);
$s = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
curl_close($ch);
iam_test_ok($s === 401, "/api/refresh.php refuse un refresh_token OAuth (HTTP $s)");

[$s, $r] = $refresh($t1, $client['client_id'], $client['secret']);
iam_test_ok($s === 400 && ($r['error'] ?? '') === 'invalid_grant', "Réutilisation d'un ancien refresh_token → 400 invalid_grant (HTTP $s)");
iam_test_ok($auditReason($withRole['id']) === 'token_reuse', 'Audit oauth_refresh_failed : raison token_reuse');

[$s, $r] = $refresh($t3, $client['client_id'], $client['secret']);
iam_test_ok($s === 400 && ($r['error'] ?? '') === 'invalid_grant', "Après un rejeu, toute la lignée est révoquée (dernier jeton refusé, HTTP $s)");

$failures = $GLOBALS['iam_test_failures'];
$fx->cleanup();
echo "\n" . ($failures === 0 ? "RÉSULTAT : tout est conforme.\n" : "RÉSULTAT : $failures anomalie(s).\n");
exit($failures === 0 ? 0 : 1);
