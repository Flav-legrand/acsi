<?php

namespace App\Providers;

use App\Console\Commands\IamCheck;
use App\Console\Commands\IamTestLogin;
use App\Iam\IamClient;
use App\Iam\IamUser;
use Illuminate\Support\Facades\Blade;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\View;
use Illuminate\Support\ServiceProvider;

/**
 * Branchement de l'IAM-Local dans Laravel.
 *
 *  - IamClient en singleton, configuré par config/services.php (clé « iam ») ;
 *  - directive Blade @iamcan('code', ...) … @endiamcan pour CACHER ;
 *  - Gate::before : @can(<code partenaires.*>) et $user->can(...) lisent
 *    aussi les permissions IAM ;
 *  - $iamUser partagé avec toutes les vues ;
 *  - commandes artisan iam:check et iam:test-login.
 */
class IamServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(IamClient::class, fn () => new IamClient((array) config('services.iam', [])));
    }

    public function boot(): void
    {
        Blade::if('iamcan', fn (string ...$codes) => IamUser::current()?->can(...$codes) ?? false);
        Blade::if('iamrole', fn (string ...$roles) => IamUser::current()?->hasRole(...$roles) ?? false);

        // Les codes de cette application commencent par « partenaires. » :
        // ceux-là sont tranchés par l'IAM ; les autres capacités restent
        // à vos Policies / Gates habituelles (return null = sans avis).
        Gate::before(function ($user, string $ability) {
            if (! str_starts_with($ability, 'partenaires.')) {
                return null;
            }

            return IamUser::current()?->can($ability) ?? false;
        });

        View::composer('*', function ($view) {
            $view->with('iamUser', IamUser::current());
        });

        if ($this->app->runningInConsole()) {
            $this->commands([IamCheck::class, IamTestLogin::class]);
        }
    }
}
