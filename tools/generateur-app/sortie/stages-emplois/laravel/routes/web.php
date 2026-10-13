<?php

use App\Http\Controllers\IamAuthController;
use App\Http\Controllers\ModuleController;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| Gestion des Stages et Emplois — routes web
|--------------------------------------------------------------------------
| Généré le 2026-10-13 par tools/generateur-app (pile laravel).
|
| Authentification : IAM-Local (OIDC + PKCE, SSO maison en option).
|   iam.auth                → utilisateur connecté via l'IAM, avec un rôle
|                             sur l'application
|   iam.permission:<code>   → permission IAM exigée (plusieurs = l'une d'elles)
*/

// ── Authentification IAM (publique) ───────────────────────────────
Route::get('/login', [IamAuthController::class, 'login'])->name('iam.login');
Route::get('/login/oidc', [IamAuthController::class, 'loginOidc'])->name('iam.login.oidc');
Route::get('/login/sso', [IamAuthController::class, 'loginSso'])->name('iam.login.sso');
Route::get('/callback', [IamAuthController::class, 'callback'])->name('iam.callback');
Route::get('/callback/sso', [IamAuthController::class, 'callbackSso'])->name('iam.callback.sso');
Route::get('/logged-out', [IamAuthController::class, 'loggedOut'])->name('iam.logged-out');
Route::post('/logout', [IamAuthController::class, 'logout'])->name('iam.logout');

// ── Application (connexion IAM obligatoire) ───────────────────────
Route::middleware('iam.auth')->group(function () {
    Route::get('/', [ModuleController::class, 'home'])->name('home');

    // Diagnostic de session : environnement local uniquement.
    if (app()->environment('local')) {
        Route::get('/iam/me', [IamAuthController::class, 'me'])->name('iam.me');
    }

    // Modules : une permission IAM par action.
    // Candidatures
    Route::prefix('candidatures')->name('candidatures.')->controller(ModuleController::class)->group(function () {
        Route::get('/', 'index')->name('index')->defaults('module', 'candidatures')->middleware('iam.permission:stages-emplois.candidatures.view');
        Route::get('/create', 'create')->name('create')->defaults('module', 'candidatures')->middleware('iam.permission:stages-emplois.candidatures.create');
        Route::post('/', 'store')->name('store')->defaults('module', 'candidatures')->middleware('iam.permission:stages-emplois.candidatures.create');
        Route::get('/export', 'export')->name('export')->defaults('module', 'candidatures')->middleware('iam.permission:stages-emplois.candidatures.export');
        Route::get('/{id}/edit', 'edit')->name('edit')->defaults('module', 'candidatures')->middleware('iam.permission:stages-emplois.candidatures.edit');
        Route::put('/{id}', 'update')->name('update')->defaults('module', 'candidatures')->middleware('iam.permission:stages-emplois.candidatures.edit');
        Route::delete('/{id}', 'destroy')->name('destroy')->defaults('module', 'candidatures')->middleware('iam.permission:stages-emplois.candidatures.delete');
    });

    // Conventions de stage
    Route::prefix('conventions')->name('conventions.')->controller(ModuleController::class)->group(function () {
        Route::get('/', 'index')->name('index')->defaults('module', 'conventions')->middleware('iam.permission:stages-emplois.conventions.view');
        Route::get('/create', 'create')->name('create')->defaults('module', 'conventions')->middleware('iam.permission:stages-emplois.conventions.create');
        Route::post('/', 'store')->name('store')->defaults('module', 'conventions')->middleware('iam.permission:stages-emplois.conventions.create');
        Route::get('/export', 'export')->name('export')->defaults('module', 'conventions')->middleware('iam.permission:stages-emplois.conventions.export');
        Route::get('/{id}/edit', 'edit')->name('edit')->defaults('module', 'conventions')->middleware('iam.permission:stages-emplois.conventions.edit');
        Route::put('/{id}', 'update')->name('update')->defaults('module', 'conventions')->middleware('iam.permission:stages-emplois.conventions.edit');
        Route::delete('/{id}', 'destroy')->name('destroy')->defaults('module', 'conventions')->middleware('iam.permission:stages-emplois.conventions.delete');
    });

    // Employés
    Route::prefix('employes')->name('employes.')->controller(ModuleController::class)->group(function () {
        Route::get('/', 'index')->name('index')->defaults('module', 'employes')->middleware('iam.permission:stages-emplois.employes.view');
        Route::get('/create', 'create')->name('create')->defaults('module', 'employes')->middleware('iam.permission:stages-emplois.employes.create');
        Route::post('/', 'store')->name('store')->defaults('module', 'employes')->middleware('iam.permission:stages-emplois.employes.create');
        Route::get('/export', 'export')->name('export')->defaults('module', 'employes')->middleware('iam.permission:stages-emplois.employes.export');
        Route::get('/{id}/edit', 'edit')->name('edit')->defaults('module', 'employes')->middleware('iam.permission:stages-emplois.employes.edit');
        Route::put('/{id}', 'update')->name('update')->defaults('module', 'employes')->middleware('iam.permission:stages-emplois.employes.edit');
        Route::delete('/{id}', 'destroy')->name('destroy')->defaults('module', 'employes')->middleware('iam.permission:stages-emplois.employes.delete');
    });

    // Offres d'emploi
    Route::prefix('offres-emploi')->name('offres-emploi.')->controller(ModuleController::class)->group(function () {
        Route::get('/', 'index')->name('index')->defaults('module', 'offres-emploi')->middleware('iam.permission:stages-emplois.offres-emploi.view');
        Route::get('/create', 'create')->name('create')->defaults('module', 'offres-emploi')->middleware('iam.permission:stages-emplois.offres-emploi.create');
        Route::post('/', 'store')->name('store')->defaults('module', 'offres-emploi')->middleware('iam.permission:stages-emplois.offres-emploi.create');
        Route::get('/export', 'export')->name('export')->defaults('module', 'offres-emploi')->middleware('iam.permission:stages-emplois.offres-emploi.export');
        Route::get('/{id}/edit', 'edit')->name('edit')->defaults('module', 'offres-emploi')->middleware('iam.permission:stages-emplois.offres-emploi.edit');
        Route::put('/{id}', 'update')->name('update')->defaults('module', 'offres-emploi')->middleware('iam.permission:stages-emplois.offres-emploi.edit');
        Route::delete('/{id}', 'destroy')->name('destroy')->defaults('module', 'offres-emploi')->middleware('iam.permission:stages-emplois.offres-emploi.delete');
    });

    // Rapports
    Route::prefix('rapports')->name('rapports.')->controller(ModuleController::class)->group(function () {
        Route::get('/', 'index')->name('index')->defaults('module', 'rapports')->middleware('iam.permission:stages-emplois.rapports.view');
        Route::get('/create', 'create')->name('create')->defaults('module', 'rapports')->middleware('iam.permission:stages-emplois.rapports.create');
        Route::post('/', 'store')->name('store')->defaults('module', 'rapports')->middleware('iam.permission:stages-emplois.rapports.create');
        Route::get('/export', 'export')->name('export')->defaults('module', 'rapports')->middleware('iam.permission:stages-emplois.rapports.export');
        Route::get('/{id}/edit', 'edit')->name('edit')->defaults('module', 'rapports')->middleware('iam.permission:stages-emplois.rapports.edit');
        Route::put('/{id}', 'update')->name('update')->defaults('module', 'rapports')->middleware('iam.permission:stages-emplois.rapports.edit');
        Route::delete('/{id}', 'destroy')->name('destroy')->defaults('module', 'rapports')->middleware('iam.permission:stages-emplois.rapports.delete');
    });

    // Stages
    Route::prefix('stages')->name('stages.')->controller(ModuleController::class)->group(function () {
        Route::get('/', 'index')->name('index')->defaults('module', 'stages')->middleware('iam.permission:stages-emplois.stages.view');
        Route::get('/create', 'create')->name('create')->defaults('module', 'stages')->middleware('iam.permission:stages-emplois.stages.create');
        Route::post('/', 'store')->name('store')->defaults('module', 'stages')->middleware('iam.permission:stages-emplois.stages.create');
        Route::get('/export', 'export')->name('export')->defaults('module', 'stages')->middleware('iam.permission:stages-emplois.stages.export');
        Route::get('/{id}/edit', 'edit')->name('edit')->defaults('module', 'stages')->middleware('iam.permission:stages-emplois.stages.edit');
        Route::put('/{id}', 'update')->name('update')->defaults('module', 'stages')->middleware('iam.permission:stages-emplois.stages.edit');
        Route::delete('/{id}', 'destroy')->name('destroy')->defaults('module', 'stages')->middleware('iam.permission:stages-emplois.stages.delete');
    });
});
