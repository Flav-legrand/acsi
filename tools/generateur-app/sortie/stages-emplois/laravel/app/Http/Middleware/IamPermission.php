<?php

namespace App\Http\Middleware;

use App\Iam\IamUser;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Middleware « iam.permission » : exige une permission IAM.
 *
 *   Route::get('/contacts', ...)->middleware('iam.permission:stages-emplois.contacts.view');
 *
 * Plusieurs codes = AU MOINS UN suffit :
 *   ->middleware('iam.permission:stages-emplois.rapports.view,stages-emplois.rapports.export')
 *
 * À placer APRÈS « iam.auth ». Règles : voir App\Iam\IamUser::can()
 * (joker « * », lecture seule par défaut si aucune permission reçue).
 *
 * Principe « cacher ET bloquer » : ce middleware BLOQUE ; la directive
 * Blade @iamcan(...) CACHE les liens et boutons correspondants.
 */
class IamPermission
{
    public function handle(Request $request, Closure $next, string ...$codes): Response
    {
        $user = IamUser::current();

        if (! $user) {
            return $request->expectsJson()
                ? response()->json(['error' => 'unauthenticated'], 401)
                : redirect()->route('iam.login');
        }

        if (! $user->can(...$codes)) {
            $message = 'Accès refusé : votre rôle ne permet pas cette action ('.implode(' ou ', $codes).').';

            return $request->expectsJson()
                ? response()->json(['error' => 'forbidden', 'message' => $message, 'required' => $codes], 403)
                : response()->view('iam.forbidden', ['message' => $message], 403);
        }

        return $next($request);
    }
}
