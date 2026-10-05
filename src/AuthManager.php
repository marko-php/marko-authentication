<?php

declare(strict_types=1);

namespace Marko\Authentication;

use Marko\Authentication\Config\AuthConfig;
use Marko\Authentication\Contracts\CookieJarInterface;
use Marko\Authentication\Contracts\GuardInterface;
use Marko\Authentication\Contracts\UserProviderInterface;
use Marko\Authentication\Exceptions\AuthException;
use Marko\Authentication\Guard\SessionGuard;
use Marko\Authentication\Guard\TokenGuard;
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

        $guard = $this->createGuard($driver, $name);

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
     * @throws AuthException|ConfigNotFoundException
     */
    private function createGuard(
        string $driver,
        string $name,
    ): GuardInterface {
        return match ($driver) {
            'session' => $this->createSessionGuard($name),
            'token' => $this->createTokenGuard($name),
            default => throw new AuthException(
                message: "Unknown guard driver: $driver",
                context: "Guard '$name' configured with driver '$driver'",
                suggestion: "Use 'session' or 'token' as the guard driver, or register a custom driver",
            ),
        };
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

    private function createTokenGuard(
        string $name,
    ): TokenGuard {
        return new TokenGuard(
            name: $name,
            provider: $this->provider,
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
