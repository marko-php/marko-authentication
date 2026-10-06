<?php

declare(strict_types=1);

namespace Marko\Authentication;

use Marko\Authentication\Config\AuthConfig;
use Marko\Authentication\Contracts\CookieJarInterface;
use Marko\Authentication\Contracts\GuardInterface;
use Marko\Authentication\Contracts\UserProviderInterface;
use Marko\Authentication\Exceptions\AuthException;
use Marko\Authentication\Guard\GuardDriverRegistry;
use Marko\Authentication\Guard\SessionGuard;
use Marko\Authentication\Token\RememberTokenManager;
use Marko\Config\Exceptions\ConfigNotFoundException;
use Marko\Core\Event\EventDispatcherInterface;
use Marko\Session\Contracts\SessionInterface;

class AuthManager
{
    /** @var array<string, GuardInterface> */
    private array $guards = [];

    public function __construct(
        private readonly AuthConfig $config,
        private readonly SessionInterface $session,
        private readonly UserProviderInterface $provider,
        private readonly EventDispatcherInterface $eventDispatcher,
        private readonly CookieJarInterface $cookieJar,
        private readonly RememberTokenManager $rememberTokenManager,
        private readonly GuardDriverRegistry $guardDriverRegistry = new GuardDriverRegistry(),
    ) {}

    /**
     * @throws AuthException|ConfigNotFoundException
     */
    public function guard(
        ?string $name = null,
    ): GuardInterface {
        $name ??= $this->config->defaultGuard();

        if (isset($this->guards[$name])) {
            return $this->guards[$name];
        }

        $guardsConfig = $this->config->guards();
        $guardConfig = $guardsConfig[$name] ?? [];
        $driver = $guardConfig['driver'] ?? 'session';

        $guard = $this->createGuard($driver, $name, $guardConfig);

        $this->guards[$name] = $guard;

        return $guard;
    }

    /**
     * Put a guard instance in place for a guard name, replacing any guard
     * already built for it. guard($name) returns this instance from now on.
     *
     * Used by the marko/testing HTTP test client's actingAs() to authenticate
     * a user without a login request.
     */
    public function useGuard(
        string $name,
        GuardInterface $guard,
    ): void {
        $this->guards[$name] = $guard;
    }

    /**
     * Build a guard: a driver registered in GuardDriverRegistry wins, then
     * the built-in session driver. Anything else fails loudly.
     *
     * @param array<string, mixed> $guardConfig
     * @throws AuthException|ConfigNotFoundException
     */
    private function createGuard(
        string $driver,
        string $name,
        array $guardConfig,
    ): GuardInterface {
        $guard = $this->guardDriverRegistry->create($driver, $name, $guardConfig, $this->provider);

        if ($guard !== null) {
            if ($guard->getName() !== $name) {
                throw AuthException::guardNameMismatch($name, $driver, $guard->getName());
            }

            return $guard;
        }

        if ($driver === 'session') {
            return $this->createSessionGuard($name);
        }

        if ($driver === 'token') {
            throw AuthException::tokenDriverNotInstalled($name);
        }

        throw AuthException::unknownGuardDriver(
            $name,
            $driver,
            array_values(array_unique(['session', ...$this->guardDriverRegistry->drivers()])),
        );
    }

    /**
     * @throws ConfigNotFoundException
     */
    private function createSessionGuard(
        string $name,
    ): SessionGuard {
        return new SessionGuard(
            session: $this->session,
            provider: $this->provider,
            name: $name,
            cookieJar: $this->cookieJar,
            tokenManager: $this->rememberTokenManager,
            eventDispatcher: $this->eventDispatcher,
            rememberCookiePrefix: $this->config->rememberCookiePrefix(),
        );
    }

    /**
     * @throws AuthException
     */
    public function check(): bool
    {
        return $this->guard()->check();
    }

    /**
     * @throws AuthException
     */
    public function user(): ?AuthenticatableInterface
    {
        return $this->guard()->user();
    }

    /**
     * @throws AuthException
     */
    public function id(): int|string|null
    {
        return $this->guard()->id();
    }

    /**
     * Attempt to authenticate a user using the given credentials.
     *
     * @param array<string, mixed> $credentials
     * @throws AuthException
     */
    public function attempt(
        array $credentials,
    ): bool {
        return $this->guard()->attempt($credentials);
    }

    /**
     * @throws AuthException
     */
    public function logout(): void
    {
        $this->guard()->logout();
    }
}
