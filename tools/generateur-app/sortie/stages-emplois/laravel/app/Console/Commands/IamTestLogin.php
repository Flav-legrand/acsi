<?php

namespace App\Console\Commands;

use App\Iam\IamClient;
use App\Iam\Permissions;
use DOMDocument;
use DOMXPath;
use GuzzleHttp\Client;
use GuzzleHttp\Cookie\CookieJar;
use GuzzleHttp\Psr7\UriResolver;
use GuzzleHttp\Psr7\Utils;
use Illuminate\Console\Command;
use Psr\Http\Message\ResponseInterface;
use RuntimeException;

/**
 * Simule un navigateur pour dérouler une connexion COMPLÈTE via l'IAM,
 * puis vérifie que les rôles et permissions arrivent bien dans Laravel.
 *
 *   php artisan serve --port=8002          (dans un autre terminal)
 *   php artisan iam:test-login admin.stages-emplois@acsi.local
 *   php artisan iam:test-login gestionnaire.stages-emplois@acsi.local --mode=sso
 *
 * Étapes : /login/<mode> → formulaire IAM → MFA (code affiché en mode
 * démo, sinon demandé) → consentement OIDC → /callback → /iam/me →
 * comparaison avec la matrice déclarée → contrôle d'accès page par page
 * (200 attendu si permis, 403 sinon) → déconnexion.
 *
 * Nécessite APP_ENV=local (route de diagnostic /iam/me).
 */
class IamTestLogin extends Command
{
    protected $signature = 'iam:test-login
        {identifier : e-mail ou identifiant IAM}
        {--password= : mot de passe IAM (demandé si absent)}
        {--mode=oidc : oidc | sso}
        {--otp= : code MFA (sinon lu sur la page en mode démo, ou demandé)}
        {--app-url= : URL de l\'application (défaut : APP_URL)}';

    protected $description = 'Teste une connexion IAM de bout en bout et vérifie rôles et permissions';

    private Client $http;

    private int $failures = 0;

    public function handle(IamClient $iam): int
    {
        $appUrl = rtrim((string) ($this->option('app-url') ?: config('app.url')), '/');
        $mode = $this->option('mode') === 'sso' ? 'sso' : 'oidc';
        $identifier = (string) $this->argument('identifier');
        $password = (string) ($this->option('password') ?? $this->secret("Mot de passe IAM de {$identifier}"));

        $this->http = new Client([
            'cookies'         => new CookieJar(),
            'allow_redirects' => false,
            'http_errors'     => false,
            'timeout'         => 20,
            'headers'         => ['User-Agent' => 'iam-test-login/1.0 (Laravel)'],
        ]);

        $this->info("== Connexion {$mode} de {$identifier} sur {$appUrl}");

        // 1. Parcours navigateur jusqu'au retour dans l'application
        try {
            [$url, $response] = $this->browse("{$appUrl}/login/{$mode}", $appUrl, $identifier, $password);
        } catch (RuntimeException $e) {
            $this->error('  ✘ '.$e->getMessage());

            return self::FAILURE;
        }
        $this->check($response->getStatusCode() === 200, "Retour dans l'application ({$url}) : HTTP {$response->getStatusCode()}");

        // 2. État IAM vu par Laravel
        $me = json_decode((string) $this->http->get("{$appUrl}/iam/me", ['headers' => ['Accept' => 'application/json']])->getBody(), true);
        if (! is_array($me) || empty($me['user'])) {
            $this->error('  ✘ /iam/me ne renvoie pas de session IAM (APP_ENV=local ?)');

            return self::FAILURE;
        }
        $this->line('  Utilisateur : '.$me['user']['email'].' (sub '.$me['user']['id'].', mode '.$me['mode'].')');
        $this->line('  Rôles       : '.implode(', ', $me['roles']));
        $this->line('  Permissions : '.count($me['permissions']).' reçue(s)');
        $this->check($me['mode'] === $mode, "Session ouverte par la voie {$mode}");

        // 3. Comparaison avec la matrice déclarée dans l'IAM
        $account = collect(Permissions::TEST_USERS)->first(
            fn ($u) => strcasecmp($u['email'], $identifier) === 0 || strcasecmp($u['username'], $identifier) === 0
        );
        if ($account) {
            $expectedRoles = $account['roles'];
            $expectedPerms = [];
            foreach ($expectedRoles as $role) {
                $expectedPerms = array_merge($expectedPerms, Permissions::ROLE_MATRIX[$role] ?? []);
            }
            if (in_array('admin', $expectedRoles, true)) {
                $expectedPerms[] = '*';
            }
            $expectedPerms = array_values(array_unique($expectedPerms));
            sort($expectedRoles);
            sort($expectedPerms);
            $gotRoles = $me['roles'];
            $gotPerms = $me['permissions'];
            sort($gotRoles);
            sort($gotPerms);

            $this->check($gotRoles === $expectedRoles, 'Rôles conformes : '.implode(', ', $expectedRoles));
            $missing = array_diff($expectedPerms, $gotPerms);
            $extra = array_diff($gotPerms, $expectedPerms);
            $this->check($missing === [] && $extra === [], sprintf(
                'Permissions conformes à la matrice (%d attendues)%s%s',
                count($expectedPerms),
                $missing ? ' — manquantes : '.implode(', ', $missing) : '',
                $extra ? ' — en trop : '.implode(', ', $extra) : '',
            ));
        } else {
            $this->warn("  ! {$identifier} n'est pas un compte de test connu : comparaison à la matrice ignorée.");
        }

        // 4. Cacher ET bloquer : chaque écran répond 200 si permis, 403 sinon
        $this->line('  Contrôle d\'accès page par page :');
        $perms = $me['permissions'];
        $allowedFor = fn (string $code) => in_array('*', $perms, true) || in_array($code, $perms, true);
        $rows = [];
        foreach (Permissions::MODULES as $module => $def) {
            $row = [$module];
            foreach (['view' => '', 'create' => '/create', 'edit' => '/1/edit', 'export' => '/export'] as $action => $suffix) {
                if (! isset($def['actions'][$action])) {
                    $row[] = '—';
                    continue;
                }
                $status = $this->http->get("{$appUrl}/{$module}{$suffix}")->getStatusCode();
                $expected = $allowedFor($def['actions'][$action]) ? 200 : 403;
                $ok = $status === $expected;
                $this->failures += $ok ? 0 : 1;
                $row[] = ($ok ? '✔ ' : '✘ ').$status;
            }
            $rows[] = $row;
        }
        $this->table(['module', 'view', 'create', 'edit', 'export'], $rows);

        // 5. Déconnexion
        $home = (string) $this->http->get("{$appUrl}/")->getBody();
        if (preg_match('/name="_token" value="([^"]+)"/', $home, $m)) {
            $out = $this->http->post("{$appUrl}/logout", ['form_params' => ['_token' => $m[1]]]);
            $location = $out->getHeaderLine('Location');
            $this->check(str_contains($location, '/logout.php'), 'Déconnexion : redirection vers la déconnexion IAM');
            $back = $this->http->get($location);
            $this->check(str_starts_with($back->getHeaderLine('Location'), "{$appUrl}/logged-out"), "Retour sur {$appUrl}/logged-out après la déconnexion IAM");
            $after = $this->http->get("{$appUrl}/", ['headers' => ['Accept' => 'application/json']]);
            $this->check($after->getStatusCode() === 401, 'Après déconnexion, l\'application exige une nouvelle connexion');
        }

        $this->newLine();
        if ($this->failures === 0) {
            $this->info('RÉSULTAT : tout est conforme.');

            return self::SUCCESS;
        }
        $this->error("RÉSULTAT : {$this->failures} anomalie(s).");

        return self::FAILURE;
    }

    /**
     * Suit redirections et formulaires IAM comme le ferait un navigateur,
     * jusqu'à revenir sur l'application.
     *
     * @return array{0: string, 1: ResponseInterface}
     */
    private function browse(string $start, string $appUrl, string $identifier, string $password): array
    {
        $url = $start;
        $method = 'GET';
        $form = [];
        $loginDone = $mfaDone = $consentDone = false;

        for ($step = 0; $step < 30; $step++) {
            $response = $this->http->request($method, $url, $method === 'POST' ? ['form_params' => $form] : []);
            $status = $response->getStatusCode();

            if ($status >= 300 && $status < 400) {
                $url = (string) UriResolver::resolve(Utils::uriFor($url), Utils::uriFor($response->getHeaderLine('Location')));
                $method = 'GET';
                $form = [];
                continue;
            }
            if (str_starts_with($url, $appUrl) && $step > 0) {
                return [$url, $response];
            }

            $html = (string) $response->getBody();
            $fields = $this->formFields($html);

            if (isset($fields['identifier']) && ! $loginDone) {
                $this->line('  → formulaire de connexion IAM');
                $fields['identifier'] = $identifier;
                $fields['password'] = $password;
                $loginDone = true;
            } elseif (isset($fields['code']) && ! $mfaDone) {
                $code = $this->option('otp');
                if (! $code && preg_match('/class="mono"[^>]*>\s*(\d{6})\s*</', $html, $m)) {
                    $code = $m[1];
                    $this->line('  → MFA : code lu sur la page (mode démo, SMTP non configuré)');
                }
                $code = $code ?: $this->ask('Code MFA reçu par e-mail');
                $fields['code'] = (string) $code;
                $mfaDone = true;
            } elseif (isset($fields['approve']) && ! $consentDone) {
                $this->line('  → consentement OIDC : Autoriser');
                $fields['approve'] = '1';
                $consentDone = true;
            } else {
                $hint = $this->pageMessage($html);
                throw new RuntimeException("Page inattendue sur {$url} (HTTP {$status})".($hint ? " : {$hint}" : ''));
            }

            $method = 'POST';
            $form = $fields;
            // action="" : le formulaire est renvoyé à l'URL courante
        }

        throw new RuntimeException('Trop d\'étapes : boucle de redirection ?');
    }

    /** Champs du PREMIER formulaire POST de la page (consentement : « Autoriser »). */
    private function formFields(string $html): array
    {
        if (! str_contains($html, '<form')) {
            return [];
        }
        $dom = new DOMDocument();
        @$dom->loadHTML('<?xml encoding="UTF-8">'.$html);
        $xpath = new DOMXPath($dom);
        $form = $xpath->query('//form[translate(@method,"post","POST")="POST"]')->item(0);
        if (! $form) {
            return [];
        }
        $fields = [];
        foreach ($xpath->query('.//input[@name]', $form) as $input) {
            $fields[$input->getAttribute('name')] = $input->getAttribute('value');
        }

        return $fields;
    }

    private function pageMessage(string $html): string
    {
        if (preg_match('/class="alert[^"]*"[^>]*>(.*?)<\/div>/s', $html, $m)) {
            return trim(preg_replace('/\s+/', ' ', strip_tags($m[1])));
        }

        return mb_substr(trim(preg_replace('/\s+/', ' ', strip_tags($html))), 0, 160);
    }

    private function check(bool $ok, string $label): void
    {
        $this->failures += $ok ? 0 : 1;
        $ok ? $this->line("  <info>✔</info> {$label}") : $this->line("  <error>✘</error> {$label}");
    }
}
