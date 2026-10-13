<?php

namespace App\Http\Middleware;

use App\Iam\IamClient;
use App\Iam\IamException;
use App\Iam\IamUser;
use App\Models\User;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Symfony\Component\HttpFoundation\Response;

/**
 * Middleware « iam.auth » : exige un utilisateur authentifié par l'IAM.
 *
 * Deux sources d'identité :
 *
 *  1. En-tête « Authorization: Bearer <access_token> » (appels d'API) :
 *     le JWT est vérifié à chaque requête — signature RS256 avec la clé
 *     publique de l'IAM, expiration, émetteur, audience (client_id).
 *     Aucune session n'est créée.
 *
 *  2. Session web, ouverte par /callback (OIDC) ou /callback/sso :
 *     - OIDC : l'access token stocké est revérifié à chaque requête ;
 *       expiré, il est renouvelé par le refresh token (rotation côté
 *       IAM), ce qui met aussi à jour rôles et permissions ;
 *     - SSO maison : pas de jeton vérifiable, la session locale expire
 *       après IAM_SSO_SESSION_TTL secondes.
 *
 * Dans les deux cas l'utilisateur doit avoir accès à l'application
 * (au moins un rôle dessus), sinon 403.
 */
class IamAuth
{
    public function __construct(private readonly IamClient $iam)
    {
    }

    public function handle(Request $request, Closure $next): Response
    {
        $bearer = $request->bearerToken();
        if ($bearer !== null && $bearer !== '') {
            return $this->handleBearer($request, $next, $bearer);
        }

        // Route sans session (groupe « api ») : seul le jeton Bearer vaut.
        if (! $request->hasSession()) {
            return response()->json(['error' => 'unauthenticated', 'message' => 'Jeton Bearer IAM requis.'], 401)
                ->header('WWW-Authenticate', 'Bearer');
        }

        $state = $request->session()->get(IamClient::SESSION_KEY);
        if (! is_array($state)) {
            return $this->unauthenticated($request);
        }

        try {
            $state = $this->freshState($state);
        } catch (IamException $e) {
            IamClient::log('Session IAM invalidée : '.$e->getMessage(), ['email' => $state['user']['email'] ?? null]);
            $this->forget($request);

            return $this->unauthenticated($request, 'Votre session a expiré. Veuillez vous reconnecter.');
        }
        $request->session()->put(IamClient::SESSION_KEY, $state);

        $user = IamUser::fromState($state, (bool) $this->iam->config('readonly_fallback', true));
        if (! $user->hasAccess()) {
            return $this->forbidden($request, "Votre compte IAM n'a aucun rôle sur cette application.");
        }

        // Garde Laravel : auth()->user() = enregistrement local lié à l'IAM.
        if (! Auth::check() || (string) Auth::user()->iam_sub !== (string) $user->id()) {
            $local = User::where('iam_sub', (string) $user->id())->first();
            if (! $local) {
                $this->forget($request);

                return $this->unauthenticated($request);
            }
            Auth::login($local);
        }

        $request->attributes->set('iam_user', $user);

        return $next($request);
    }

    private function handleBearer(Request $request, Closure $next, string $jwt): Response
    {
        try {
            $claims = $this->iam->verifyJwt($jwt);
        } catch (IamException $e) {
            return response()->json(['error' => 'invalid_token', 'message' => $e->getMessage()], 401)
                ->header('WWW-Authenticate', 'Bearer error="invalid_token"');
        }

        $user = new IamUser(
            ['id' => (int) ($claims['sub'] ?? 0), 'username' => '', 'email' => '', 'first_name' => '', 'last_name' => '', 'name' => ''],
            array_values(array_map('strval', (array) ($claims['roles'] ?? []))),
            array_values(array_map('strval', (array) ($claims['permissions'] ?? []))),
            'bearer',
            (bool) $this->iam->config('readonly_fallback', true),
        );
        if (! $user->hasAccess()) {
            return response()->json(['error' => 'forbidden', 'message' => "Aucun rôle sur l'application."], 403);
        }
        $request->attributes->set('iam_user', $user);

        return $next($request);
    }

    /** Revérifie (et au besoin renouvelle) l'état IAM de la session. */
    private function freshState(array $state): array
    {
        if (($state['mode'] ?? '') === 'sso') {
            if ((int) ($state['expires_at'] ?? 0) < time()) {
                throw new IamException('session SSO expirée');
            }

            return $state;
        }

        // OIDC : renouveler 30 s avant l'expiration de l'access token.
        if ((int) ($state['expires_at'] ?? 0) - 30 <= time()) {
            if (empty($state['refresh_token'])) {
                throw new IamException('access token expiré, pas de refresh token');
            }
            $tokens = $this->iam->refresh((string) $state['refresh_token']);
            $access = $this->iam->verifyJwt((string) $tokens['access_token']);
            $id = ! empty($tokens['id_token']) ? $this->iam->verifyJwt((string) $tokens['id_token']) : [];
            $renewed = $this->iam->stateFromOidc($tokens, $id + ['sub' => $access['sub'] ?? null], $access);
            // L'id_token d'un refresh ne porte pas toujours le profil :
            // on conserve l'identité obtenue à la connexion.
            $renewed['user'] = $state['user'];
            $renewed['logged_in_at'] = $state['logged_in_at'] ?? time();
            IamClient::log('Jetons renouvelés', ['email' => $state['user']['email'] ?? null]);

            return $renewed;
        }

        // Revérification de l'access token à chaque requête (clé JWKS en cache).
        $claims = $this->iam->verifyJwt((string) $state['access_token']);
        if ((string) ($claims['sub'] ?? '') !== (string) ($state['user']['id'] ?? '')) {
            throw new IamException('le jeton ne correspond pas à l’utilisateur de la session');
        }

        return $state;
    }

    private function forget(Request $request): void
    {
        $request->session()->forget(IamClient::SESSION_KEY);
        Auth::logout();
    }

    private function unauthenticated(Request $request, ?string $message = null): Response
    {
        if ($request->expectsJson()) {
            return response()->json(['error' => 'unauthenticated', 'message' => $message ?? 'Authentification IAM requise.'], 401);
        }
        $request->session()->put('url.intended', $request->fullUrl());
        if ($message) {
            $request->session()->flash('iam_notice', $message);
        }

        return redirect()->route('iam.login');
    }

    private function forbidden(Request $request, string $message): Response
    {
        if ($request->expectsJson()) {
            return response()->json(['error' => 'forbidden', 'message' => $message], 403);
        }

        return response()->view('iam.forbidden', ['message' => $message], 403);
    }
}
