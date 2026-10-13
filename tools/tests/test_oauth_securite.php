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

$failures = $GLOBALS['iam_test_failures'];
$fx->cleanup();
echo "\n" . ($failures === 0 ? "RÉSULTAT : tout est conforme.\n" : "RÉSULTAT : $failures anomalie(s).\n");
exit($failures === 0 ? 0 : 1);
