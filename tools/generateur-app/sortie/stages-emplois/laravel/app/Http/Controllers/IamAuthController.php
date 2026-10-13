<?php

namespace App\Http\Controllers;

use App\Iam\IamClient;
use App\Iam\IamException;
use App\Iam\IamUser;
use App\Models\User;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Symfony\Component\HttpFoundation\Response;

/**
 * Connexion / déconnexion de Gestion des Stages et Emplois via l'IAM-Local.
 *
 *   GET  /login           → voie par défaut (IAM_AUTH_MODE : oidc | sso)
 *   GET  /login/oidc      → OIDC + PKCE
 *   GET  /login/sso       → SSO maison
 *   GET  /callback        → retour OIDC (?code=&state=)
 *   GET  /callback/sso    → retour SSO maison (?sso_token=)
 *   POST /logout          → déconnexion locale puis IAM
 *   GET  /logged-out      → page publique après déconnexion
 */
class IamAuthController extends Controller
{
    public function __construct(private readonly IamClient $iam)
    {
    }

    public function login(Request $request): RedirectResponse
    {
        return $this->iam->mode() === 'sso' ? $this->loginSso($request) : $this->loginOidc($request);
    }

    /* ------------------------------------------------------------
       OIDC + PKCE
       ------------------------------------------------------------ */

    public function loginOidc(Request $request): RedirectResponse
    {
        $auth = $this->iam->buildAuthorizationRequest();

        // Le verifier PKCE, le state et le nonce restent côté serveur.
        $request->session()->put('iam_oidc', [
            'state'    => $auth['state'],
            'nonce'    => $auth['nonce'],
            'verifier' => $auth['verifier'],
            'at'       => time(),
        ]);

        return redirect()->away($auth['url']);
    }

    public function callback(Request $request): Response
    {
        $pending = $request->session()->pull('iam_oidc');

        if ($request->filled('error')) {
            return $this->failed($request, 'Connexion refusée par l’IAM : '.$request->query('error_description', $request->query('error')));
        }
        if (! is_array($pending) || ! hash_equals((string) $pending['state'], (string) $request->query('state'))) {
            return $this->failed($request, 'Réponse de l’IAM inattendue (state invalide ou expiré). Recommencez la connexion.');
        }
        if (time() - (int) $pending['at'] > 600) {
            return $this->failed($request, 'La demande de connexion a expiré. Recommencez.');
        }

        try {
            $tokens = $this->iam->exchangeCode((string) $request->query('code'), (string) $pending['verifier']);
            if (empty($tokens['id_token'])) {
                throw new IamException('l’IAM n’a pas renvoyé d’id_token (scope openid manquant ?)');
            }
            $idClaims = $this->iam->verifyJwt((string) $tokens['id_token'], (string) $pending['nonce']);
            $accessClaims = $this->iam->verifyJwt((string) $tokens['access_token']);
            if ((string) ($idClaims['sub'] ?? '') !== (string) ($accessClaims['sub'] ?? '-')) {
                throw new IamException('id_token et access_token désignent deux utilisateurs différents');
            }
        } catch (IamException $e) {
            IamClient::log('Échec OIDC : '.$e->getMessage());

            return $this->failed($request, $e->getMessage());
        }

        return $this->open($request, $this->iam->stateFromOidc($tokens, $idClaims, $accessClaims));
    }

    /* ------------------------------------------------------------
       SSO maison (option)
       ------------------------------------------------------------ */

    public function loginSso(Request $request): RedirectResponse
    {
        return redirect()->away($this->iam->ssoAuthorizeUrl(
            route('iam.callback.sso'),
            (bool) $this->iam->config('sso_prompt', false),
        ));
    }

    public function callbackSso(Request $request): Response
    {
        $token = (string) $request->query('sso_token', '');
        if ($token === '') {
            return $this->failed($request, 'Jeton SSO absent.');
        }

        try {
            $data = $this->iam->validateSsoToken($token);
        } catch (IamException $e) {
            IamClient::log('Échec SSO : '.$e->getMessage());

            return $this->failed($request, $e->getMessage());
        }

        return $this->open($request, $this->iam->stateFromSso($data));
    }

    /* ------------------------------------------------------------
       Ouverture de session (commun aux deux voies)
       ------------------------------------------------------------ */

    private function open(Request $request, array $state): Response
    {
        $iamUser = IamUser::fromState($state, (bool) $this->iam->config('readonly_fallback', true));
        if (! $iamUser->hasAccess()) {
            IamClient::log('Accès refusé : aucun rôle', ['email' => $iamUser->email()]);

            return response()->view('iam.forbidden', [
                'message' => "Votre compte IAM ({$iamUser->email()}) n'a aucun rôle sur cette application. Contactez l'administrateur IAM.",
            ], 403);
        }

        // Enregistrement local (provisionnement à la volée) : permet aux
        // tables métier de référencer users.id et à auth()->user() de
        // fonctionner. L'IAM reste la seule source des droits.
        $local = User::where('iam_sub', (string) $iamUser->id())->first()
            ?? User::where('email', $iamUser->email())->first()
            ?? new User(['password' => Hash::make(Str::random(48))]);
        $local->forceFill([
            'iam_sub' => (string) $iamUser->id(),
            'name'    => $iamUser->name() ?: $iamUser->email(),
            'email'   => $iamUser->email() ?: ($local->email ?? $iamUser->id().'@iam.local'),
        ])->save();

        $request->session()->regenerate();
        Auth::login($local);
        $request->session()->put(IamClient::SESSION_KEY, $state);

        IamClient::log('Connexion', ['email' => $iamUser->email(), 'mode' => $state['mode'], 'roles' => $iamUser->roles]);

        return redirect()->intended(route('home'));
    }

    private function failed(Request $request, string $message): Response
    {
        return response()->view('iam.error', ['message' => $message], 401);
    }

    /* ------------------------------------------------------------
       Déconnexion
       ------------------------------------------------------------ */

    public function logout(Request $request): RedirectResponse
    {
        Auth::logout();
        $request->session()->invalidate();
        $request->session()->regenerateToken();

        // Ferme aussi la session IAM : sinon un nouveau clic sur
        // « Se connecter » reconnecterait sans saisie.
        return redirect()->away($this->iam->logoutUrl());
    }

    public function loggedOut(): Response
    {
        return response()->view('iam.logged-out');
    }

    /** Diagnostic (environnement local uniquement) : état IAM de la session. */
    public function me(): Response
    {
        $user = IamUser::current();

        return response()->json($user ? $user->toArray() + ['local_user_id' => Auth::id()] : ['authenticated' => false]);
    }
}
