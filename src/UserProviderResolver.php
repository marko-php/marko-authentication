<?php

declare(strict_types=1);

namespace Marko\Authentication;

use Marko\Authentication\Config\AuthConfig;
use Marko\Authentication\Contracts\UserProviderInterface;
use Marko\Authentication\Exceptions\AuthException;
use Marko\Config\Exceptions\ConfigNotFoundException;
use Marko\Core\Container\ContainerInterface;

/**
 * Picks the user provider for a guard, so each guard can authenticate
 * against its own user store (for example admins and customers).
 *
 * A guard names its provider with its `provider` key, falling back to
 * `authentication.default.provider`. The named entry in
 * `authentication.providers` sets the provider with its `class` key, a
 * UserProviderInterface implementation resolved from the container. A guard
 * with no provider name, a provider entry without a `class`, or an app with
 * no `authentication.providers` at all uses the container's
 * UserProviderInterface binding, as a single-provider app always has.
 *
 * Providers are resolved on first use and shared per provider name.
 */
class UserProviderResolver
{
    /** @var array<string, UserProviderInterface> */
    private array $providers = [];

    private ?UserProviderInterface $boundProvider = null;

    public function __construct(
        private readonly AuthConfig $config,
        private readonly ContainerInterface $container,
    ) {}

    /**
     * @param array<string, mixed> $guardConfig
     * @throws AuthException|ConfigNotFoundException
     */
    public function forGuard(
        string $guard,
        array $guardConfig,
    ): UserProviderInterface {
        $providerName = array_key_exists('provider', $guardConfig)
            ? $guardConfig['provider']
            : $this->config->defaultProviderOrNull();

        if ($providerName === null) {
            return $this->defaultProvider();
        }

        if (!is_string($providerName) || $providerName === '') {
            throw AuthException::invalidGuardProvider($guard);
        }

        return $this->providers[$providerName] ??= $this->resolve($guard, $providerName);
    }

    /**
     * @throws AuthException|ConfigNotFoundException
     */
    private function resolve(
        string $guard,
        string $providerName,
    ): UserProviderInterface {
        $providersConfig = $this->config->providersOrNull();

        if ($providersConfig === null) {
            return $this->defaultProvider();
        }

        if (!array_key_exists($providerName, $providersConfig)) {
            throw AuthException::undefinedProvider(
                $guard,
                $providerName,
                array_map(strval(...), array_keys($providersConfig)),
            );
        }

        $providerConfig = $providersConfig[$providerName];
        $class = is_array($providerConfig) ? ($providerConfig['class'] ?? null) : null;

        if ($class === null) {
            return $this->defaultProvider();
        }

        if (!is_string($class) || !is_a($class, UserProviderInterface::class, true)) {
            throw AuthException::invalidProviderClass(
                $providerName,
                is_string($class) ? $class : get_debug_type($class),
            );
        }

        /** @var UserProviderInterface */
        return $this->container->get($class);
    }

    private function defaultProvider(): UserProviderInterface
    {
        /** @var UserProviderInterface */
        return $this->boundProvider ??= $this->container->get(UserProviderInterface::class);
    }
}
