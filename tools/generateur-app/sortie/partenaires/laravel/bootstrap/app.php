<?php

use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        commands: __DIR__.'/../routes/console.php',
        health: '/up',
    )
    ->withMiddleware(function (Middleware $middleware) {
        // IAM-Local : alias utilisés dans routes/web.php
        $middleware->alias([
            'iam.auth' => \App\Http\Middleware\IamAuth::class,
            'iam.permission' => \App\Http\Middleware\IamPermission::class,
        ]);
        // Laravel redirige les invités vers la route « login » : on la
        // fait pointer vers la connexion IAM.
        $middleware->redirectGuestsTo(fn () => route('iam.login'));
    })
    ->withExceptions(function (Exceptions $exceptions) {
        //
    })->create();
