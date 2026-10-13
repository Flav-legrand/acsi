<?php
declare(strict_types=1);

namespace IamLocal\Platforms;

final class IamServiceProvider
{
    private static ?PlatformRegistry $registry = null;

    public static function platforms(): PlatformRegistry
    {
        if (self::$registry !== null) return self::$registry;

        require_once __DIR__ . '/PlatformInterface.php';
        require_once __DIR__ . '/AbstractPlatform.php';
        require_once __DIR__ . '/PlatformRegistry.php';
        $platformClasses = [
            'laravel' => 'LaravelPlatform',
            'nextjs' => 'NextJsPlatform',
            'django' => 'DjangoPlatform',
            'php' => 'PhpPlatform',
            'symfony' => 'SymfonyPlatform',
            'nodejs' => 'NodeJsPlatform',
            'spring' => 'SpringPlatform',
            'go' => 'GoPlatform',
            'other' => 'OtherPlatform',
        ];
        foreach ($platformClasses as $className) {
            require_once __DIR__ . '/' . $className . '.php';
        }

        $registry = new PlatformRegistry();
        foreach ($platformClasses as $className) {
            $class = __NAMESPACE__ . '\\' . $className;
            $registry->register(new $class());
        }
        self::$registry = $registry;
        return $registry;
    }
}