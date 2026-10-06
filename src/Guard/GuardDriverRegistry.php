<?php

declare(strict_types=1);

namespace Marko\Authentication\Guard;

use Closure;
use Marko\Authentication\Contracts\GuardInterface;
use Marko\Authentication\Contracts\UserProviderInterface;

/**
 * Maps guard driver names (the `driver` key of a guard in
 * `authentication.guards`) to the factories that build them.
 *
 * AuthManager consults this registry before its built-in `session` driver,
 * so a registered driver can also replace `session`. Packages register their
 * drivers from a module.php `boot` callback, e.g. marko/authentication-token
 * registers `token`. Registering a driver name again replaces the earlier
 * factory, so a later module (app over vendor) can override a driver.
 *
 * A factory receives the guard name, that guard's config array and the user
 * provider, and must return a guard whose getName() is the guard name.
 */
class GuardDriverRegistry
{
    /** @var array<string, Closure(string, array<string, mixed>, UserProviderInterface): GuardInterface> */
    private array $factories = [];

    /**
     * @param Closure(string, array<string, mixed>, UserProviderInterface): GuardInterface $factory
     */
    public function extend(
        string $driver,
        Closure $factory,
    ): void {
        $this->factories[$driver] = $factory;
    }

    public function has(
        string $driver,
    ): bool {
        return isset($this->factories[$driver]);
    }

    /**
     * @return list<string>
     */
    public function drivers(): array
    {
        return array_map(strval(...), array_keys($this->factories));
    }

    /**
     * Build a guard with the factory registered for the driver, or return
     * null when no factory is registered for it.
     *
     * @param array<string, mixed> $config
     */
    public function create(
        string $driver,
        string $name,
        array $config,
        UserProviderInterface $provider,
    ): ?GuardInterface {
        if (!isset($this->factories[$driver])) {
            return null;
        }

        return ($this->factories[$driver])($name, $config, $provider);
    }
}
