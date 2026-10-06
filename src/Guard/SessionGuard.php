<?php

declare(strict_types=1);

namespace Marko\Authentication\Guard;

use DateMalformedStringException;
use DateTimeImmutable;
use Marko\Authentication\AuthenticatableInterface;
use Marko\Authentication\Contracts\CookieJarInterface;
use Marko\Authentication\Contracts\GuardInterface;
use Marko\Authentication\Contracts\LoginThrottleInterface;
use Marko\Authentication\Contracts\UserProviderInterface;
use Marko\Authentication\Event\FailedLoginEvent;
use Marko\Authentication\Event\LoginEvent;
use Marko\Authentication\Event\LogoutEvent;
use Marko\Authentication\Exceptions\AuthException;
use Marko\Authentication\Exceptions\TooManyLoginAttemptsException;
use Marko\Authentication\Token\RememberTokenManager;
use Marko\Core\Contracts\ResettableInterface;
use Marko\Core\Event\EventDispatcherInterface;
use Marko\Session\Contracts\SessionInterface;
use Override;
use Random\RandomException;

class SessionGuard implements GuardInterface, ResettableInterface
{
    private ?AuthenticatableInterface $cachedUser = null;

    public function __construct(
        private readonly SessionInterface $session,
        public UserProviderInterface $provider {
            set {
                $this->provider = $value;
            }
        },
        private readonly string $name = 'session',
        private readonly ?CookieJarInterface $cookieJar = null,
        private readonly ?RememberTokenManager $tokenManager = null,
        private readonly ?EventDispatcherInterface $eventDispatcher = null,
        private readonly string $rememberCookiePrefix = 'remember_',
        private readonly ?LoginThrottleInterface $loginThrottle = null,
    ) {}

    /**
     * @throws AuthException|DateMalformedStringException|RandomException
     */
    public function check(): bool
    {
        return $this->user() !== null;
    }

    /**
     * @throws AuthException|DateMalformedStringException|RandomException
     */
    public function guest(): bool
    {
        return !$this->check();
    }

    /**
     * @throws AuthException|DateMalformedStringException|RandomException
     */
    public function user(): ?AuthenticatableInterface
    {
        if ($this->cachedUser !== null) {
            return $this->cachedUser;
        }

        $id = $this->session->get($this->getSessionKey());

        if ($id !== null) {
            $this->cachedUser = $this->provider->retrieveById($id);

            return $this->cachedUser;
        }

        // Try to authenticate via remember token
        $this->cachedUser = $this->authenticateViaRememberCookie();

        return $this->cachedUser;
    }

    /**
     * Log the user in from the remember cookie, once per session.
     *
     * A valid, unexpired cookie goes through the same session login as a
     * password login (session key, regenerated ID, LoginEvent), so later
     * requests authenticate from the session and the cookie is not consumed
     * again until that session ends.
     *
     * @throws AuthException|DateMalformedStringException|RandomException
     */
    private function authenticateViaRememberCookie(): ?AuthenticatableInterface
    {
        if ($this->cookieJar === null || $this->tokenManager === null) {
            return null;
        }

        $cookieValue = $this->cookieJar->get($this->getRememberCookieName());

        if ($cookieValue === null) {
            return null;
        }

        $parts = explode('|', $cookieValue, 2);

        if (count($parts) !== 2) {
            return null;
        }

        [$id, $token] = $parts;

        // Providers store (and compare against) the hash, never the plain token
        $user = $this->provider->retrieveByRememberToken($id, $this->tokenManager->hash($token));

        if ($user === null) {
            return null;
        }

        // Validate the token
        $storedHash = $user->getRememberToken();

        if ($storedHash === null || !$this->tokenManager->validate($token, $storedHash)) {
            return null;
        }

        // The expiry lives server-side: the cookie's own Expires is client-controlled
        $expiresAt = $user->getRememberTokenExpiresAt();

        if ($expiresAt === null || $this->tokenManager->hasExpired($expiresAt)) {
            $this->provider->updateRememberToken($user, null, null);
            $this->cookieJar->delete($this->getRememberCookieName());

            return null;
        }

        $this->startSession($user);

        // Rotate the token (prevents replay) but keep the original expiry, so a
        // remember-me login has a fixed lifetime however often it is used
        $this->createRememberToken($user, $expiresAt);

        $this->dispatchLoginEvent($user, true);

        return $user;
    }

    /**
     * @throws AuthException|DateMalformedStringException|RandomException
     */
    public function id(): int|string|null
    {
        return $this->user()?->getAuthIdentifier();
    }

    /**
     * Throttled by the login throttle when one is set: a locked-out attempt
     * throws before the user is looked up, every failure is counted, and a
     * success clears the count.
     *
     * @param array<string, mixed> $credentials
     *
     * @throws AuthException|DateMalformedStringException|RandomException|TooManyLoginAttemptsException
     */
    public function attempt(
        array $credentials,
    ): bool {
        $this->loginThrottle?->ensureNotLockedOut($this->name, $credentials);

        $user = $this->provider->retrieveByCredentials($credentials);

        if ($user === null) {
            $this->dispatchFailedLoginEvent($credentials);

            return false;
        }

        if (!$this->provider->validateCredentials($user, $credentials)) {
            $this->dispatchFailedLoginEvent($credentials);

            return false;
        }

        // Upgrade the stored hash while the plain password is at hand (cost or algorithm changed)
        $this->provider->rehashPasswordIfNeeded($user, $credentials);

        $this->loginThrottle?->clear($this->name, $credentials);
        $this->login($user);

        return true;
    }

    /**
     * @param array<string, mixed> $credentials
     */
    private function dispatchFailedLoginEvent(
        array $credentials,
    ): void {
        // Every failed attempt counts toward the throttle, whether or not the user exists
        $this->loginThrottle?->recordFailure($this->name, $credentials);

        $this->eventDispatcher?->dispatch(new FailedLoginEvent(
            credentials: $credentials,
            guard: $this->name,
        ));
    }

    /**
     * @throws AuthException|DateMalformedStringException|RandomException
     */
    public function login(
        AuthenticatableInterface $user,
        bool $remember = false,
    ): void {
        $this->startSession($user);
        $this->cachedUser = $user;

        if ($remember) {
            $this->createRememberToken($user);
        }

        $this->dispatchLoginEvent($user, $remember);
    }

    /**
     * Store the user in the session under a fresh session ID (prevents fixation).
     *
     * @throws AuthException
     */
    private function startSession(
        AuthenticatableInterface $user,
    ): void {
        $this->ensureSessionAvailable();
        $this->session->set($this->getSessionKey(), $user->getAuthIdentifier());
        $this->session->regenerate();
    }

    private function dispatchLoginEvent(
        AuthenticatableInterface $user,
        bool $remember,
    ): void {
        $this->eventDispatcher?->dispatch(new LoginEvent(
            user: $user,
            guard: $this->name,
            remember: $remember,
        ));
    }

    /**
     * Issue a new remember token, expiring at $expiresAt (default: a full lifetime from now).
     *
     * @throws AuthException|DateMalformedStringException|RandomException
     */
    private function createRememberToken(
        AuthenticatableInterface $user,
        ?DateTimeImmutable $expiresAt = null,
    ): void {
        if ($this->cookieJar === null || $this->tokenManager === null) {
            throw AuthException::rememberMeUnavailable($this->name);
        }

        $token = $this->tokenManager->generate();
        $hashedToken = $this->tokenManager->hash($token);
        $expiresAt ??= $this->tokenManager->expiresAt();

        $this->provider->updateRememberToken($user, $hashedToken, $expiresAt);

        if (
            $user->getRememberToken() !== $hashedToken
            || $user->getRememberTokenExpiresAt()?->getTimestamp() !== $expiresAt->getTimestamp()
        ) {
            throw AuthException::rememberTokenNotStored($this->name, $this->provider::class);
        }

        $cookieValue = $user->getAuthIdentifier() . '|' . $token;
        $this->cookieJar->set(
            $this->getRememberCookieName(),
            $cookieValue,
            $this->tokenManager->minutesUntil($expiresAt),
        );
    }

    private function getSessionKey(): string
    {
        return 'auth_' . $this->name . '_user_id';
    }

    private function getRememberCookieName(): string
    {
        return $this->rememberCookiePrefix . $this->name;
    }

    /**
     * @throws AuthException
     */
    private function ensureSessionAvailable(): void
    {
        if (!$this->session->isAvailable()) {
            throw new AuthException(
                message: 'Session not started',
                context: 'SessionGuard requires an active session',
                suggestion: 'Ensure the session middleware is applied before authentication',
            );
        }
    }

    /**
     * @throws AuthException|DateMalformedStringException|RandomException
     */
    public function loginById(
        int|string $id,
    ): ?AuthenticatableInterface {
        $user = $this->provider->retrieveById($id);

        if ($user === null) {
            return null;
        }

        $this->login($user);

        return $user;
    }

    /**
     * @throws AuthException|DateMalformedStringException|RandomException
     */
    public function logout(): void
    {
        $user = $this->user();

        if ($user !== null && $this->cookieJar !== null && $this->tokenManager !== null) {
            $this->provider->updateRememberToken($user, null, null);
            $this->cookieJar->delete($this->getRememberCookieName());
        }

        $this->session->remove($this->getSessionKey());
        $this->cachedUser = null;

        if ($user !== null) {
            // A new session ID, with the old session deleted, so the logged-out ID
            // cannot be reused (shared machines, planted session cookies)
            $this->session->regenerate(true);
            $this->dispatchLogoutEvent($user);
        }
    }

    private function dispatchLogoutEvent(
        AuthenticatableInterface $user,
    ): void {
        $this->eventDispatcher?->dispatch(new LogoutEvent(
            user: $user,
            guard: $this->name,
        ));
    }

    public function getName(): string
    {
        return $this->name;
    }

    #[Override]
    public function reset(): void
    {
        $this->cachedUser = null;
    }
}
