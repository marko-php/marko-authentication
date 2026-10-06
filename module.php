<?php

declare(strict_types=1);

use Marko\Authentication\AuthManager;
use Marko\Authentication\Config\AuthConfig;
use Marko\Authentication\Contracts\CookieJarInterface;
use Marko\Authentication\Contracts\GuardInterface;
use Marko\Authentication\Contracts\PasswordHasherInterface;
use Marko\Authentication\Cookie\RequestCookieJar;
use Marko\Authentication\Guard\GuardDriverRegistry;
use Marko\Authentication\Hashing\BcryptPasswordHasher;
use Marko\Authentication\Hashing\HashManagerPasswordHasher;
use Marko\Authentication\Middleware\QueuedCookiesMiddleware;
use Marko\Authentication\Token\RememberTokenManager;
use Marko\Core\Container\ContainerInterface;
use Marko\Core\Module\ModuleManifest;
use Marko\Core\Module\ModuleRepositoryInterface;
use Psr\Clock\ClockInterface;

return [
    // Load after the session drivers so QueuedCookiesMiddleware runs inside SessionMiddleware.
    'sequence' => [
        'after' => ['marko/session-file', 'marko/session-database'],
    ],
    'bindings' => [
        PasswordHasherInterface::class => function (ContainerInterface $container): PasswordHasherInterface {
            // With marko/hashing loaded, its driver config (HASH_DRIVER) governs login passwords too
            if (
                $container->has(ModuleRepositoryInterface::class)
                && array_any(
                    $container->get(ModuleRepositoryInterface::class)->all(),
                    fn (ModuleManifest $module): bool => $module->name === 'marko/hashing',
                )
            ) {
                return $container->get(HashManagerPasswordHasher::class);
            }

            $config = $container->get(AuthConfig::class);

            return new BcryptPasswordHasher(
                cost: $config->bcryptCost(),
            );
        },
        RememberTokenManager::class => function (ContainerInterface $container): RememberTokenManager {
            return new RememberTokenManager(
                clock: $container->get(ClockInterface::class),
                lifetimeMinutes: $container->get(AuthConfig::class)->rememberLifetime(),
            );
        },
        // The guard and QueuedCookiesMiddleware must share one jar so queued cookies reach the response.
        CookieJarInterface::class => function (ContainerInterface $container): CookieJarInterface {
            return $container->get(RequestCookieJar::class);
        },
        GuardInterface::class => function (ContainerInterface $container): GuardInterface {
            return $container->get(AuthManager::class)->guard();
        },
    ],
    'singletons' => [
        AuthManager::class,
        // Drivers registered from module boot callbacks must reach the AuthManager.
        GuardDriverRegistry::class,
        GuardInterface::class,
        RequestCookieJar::class,
        CookieJarInterface::class,
        RememberTokenManager::class,
    ],
    'globalMiddleware' => [
        QueuedCookiesMiddleware::class,
    ],
];
