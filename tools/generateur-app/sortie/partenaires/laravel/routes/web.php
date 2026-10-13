<?php

use App\Http\Controllers\IamAuthController;
use App\Http\Controllers\ModuleController;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| Gestion des Partenaires — routes web
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
    // Contacts
    Route::prefix('contacts')->name('contacts.')->controller(ModuleController::class)->group(function () {
        Route::get('/', 'index')->name('index')->defaults('module', 'contacts')->middleware('iam.permission:partenaires.contacts.view');
        Route::get('/create', 'create')->name('create')->defaults('module', 'contacts')->middleware('iam.permission:partenaires.contacts.create');
        Route::post('/', 'store')->name('store')->defaults('module', 'contacts')->middleware('iam.permission:partenaires.contacts.create');
        Route::get('/export', 'export')->name('export')->defaults('module', 'contacts')->middleware('iam.permission:partenaires.contacts.export');
        Route::get('/{id}/edit', 'edit')->name('edit')->defaults('module', 'contacts')->middleware('iam.permission:partenaires.contacts.edit');
        Route::put('/{id}', 'update')->name('update')->defaults('module', 'contacts')->middleware('iam.permission:partenaires.contacts.edit');
        Route::delete('/{id}', 'destroy')->name('destroy')->defaults('module', 'contacts')->middleware('iam.permission:partenaires.contacts.delete');
    });

    // Conventions
    Route::prefix('conventions')->name('conventions.')->controller(ModuleController::class)->group(function () {
        Route::get('/', 'index')->name('index')->defaults('module', 'conventions')->middleware('iam.permission:partenaires.conventions.view');
        Route::get('/create', 'create')->name('create')->defaults('module', 'conventions')->middleware('iam.permission:partenaires.conventions.create');
        Route::post('/', 'store')->name('store')->defaults('module', 'conventions')->middleware('iam.permission:partenaires.conventions.create');
        Route::get('/export', 'export')->name('export')->defaults('module', 'conventions')->middleware('iam.permission:partenaires.conventions.export');
        Route::get('/{id}/edit', 'edit')->name('edit')->defaults('module', 'conventions')->middleware('iam.permission:partenaires.conventions.edit');
        Route::put('/{id}', 'update')->name('update')->defaults('module', 'conventions')->middleware('iam.permission:partenaires.conventions.edit');
        Route::delete('/{id}', 'destroy')->name('destroy')->defaults('module', 'conventions')->middleware('iam.permission:partenaires.conventions.delete');
    });

    // Documents
    Route::prefix('documents')->name('documents.')->controller(ModuleController::class)->group(function () {
        Route::get('/', 'index')->name('index')->defaults('module', 'documents')->middleware('iam.permission:partenaires.documents.view');
        Route::get('/create', 'create')->name('create')->defaults('module', 'documents')->middleware('iam.permission:partenaires.documents.create');
        Route::post('/', 'store')->name('store')->defaults('module', 'documents')->middleware('iam.permission:partenaires.documents.create');
        Route::get('/export', 'export')->name('export')->defaults('module', 'documents')->middleware('iam.permission:partenaires.documents.export');
        Route::get('/{id}/edit', 'edit')->name('edit')->defaults('module', 'documents')->middleware('iam.permission:partenaires.documents.edit');
        Route::put('/{id}', 'update')->name('update')->defaults('module', 'documents')->middleware('iam.permission:partenaires.documents.edit');
        Route::delete('/{id}', 'destroy')->name('destroy')->defaults('module', 'documents')->middleware('iam.permission:partenaires.documents.delete');
    });

    // Partenaires
    Route::prefix('partenaires')->name('partenaires.')->controller(ModuleController::class)->group(function () {
        Route::get('/', 'index')->name('index')->defaults('module', 'partenaires')->middleware('iam.permission:partenaires.partenaires.view');
        Route::get('/create', 'create')->name('create')->defaults('module', 'partenaires')->middleware('iam.permission:partenaires.partenaires.create');
        Route::post('/', 'store')->name('store')->defaults('module', 'partenaires')->middleware('iam.permission:partenaires.partenaires.create');
        Route::get('/export', 'export')->name('export')->defaults('module', 'partenaires')->middleware('iam.permission:partenaires.partenaires.export');
        Route::get('/{id}/edit', 'edit')->name('edit')->defaults('module', 'partenaires')->middleware('iam.permission:partenaires.partenaires.edit');
        Route::put('/{id}', 'update')->name('update')->defaults('module', 'partenaires')->middleware('iam.permission:partenaires.partenaires.edit');
        Route::delete('/{id}', 'destroy')->name('destroy')->defaults('module', 'partenaires')->middleware('iam.permission:partenaires.partenaires.delete');
    });

    // Rapports
    Route::prefix('rapports')->name('rapports.')->controller(ModuleController::class)->group(function () {
        Route::get('/', 'index')->name('index')->defaults('module', 'rapports')->middleware('iam.permission:partenaires.rapports.view');
        Route::get('/create', 'create')->name('create')->defaults('module', 'rapports')->middleware('iam.permission:partenaires.rapports.create');
        Route::post('/', 'store')->name('store')->defaults('module', 'rapports')->middleware('iam.permission:partenaires.rapports.create');
        Route::get('/export', 'export')->name('export')->defaults('module', 'rapports')->middleware('iam.permission:partenaires.rapports.export');
        Route::get('/{id}/edit', 'edit')->name('edit')->defaults('module', 'rapports')->middleware('iam.permission:partenaires.rapports.edit');
        Route::put('/{id}', 'update')->name('update')->defaults('module', 'rapports')->middleware('iam.permission:partenaires.rapports.edit');
        Route::delete('/{id}', 'destroy')->name('destroy')->defaults('module', 'rapports')->middleware('iam.permission:partenaires.rapports.delete');
    });
});
