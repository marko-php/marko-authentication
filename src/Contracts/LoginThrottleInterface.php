<?php

declare(strict_types=1);

namespace Marko\Authentication\Contracts;

use Marko\Authentication\Exceptions\TooManyLoginAttemptsException;

/**
 * Limits password guessing against one account from one client.
 *
 * SessionGuard::attempt() calls ensureNotLockedOut() before it looks the user
 * up, recordFailure() after every rejected attempt and clear() after a
 * successful one, so every login path through the guard is throttled.
 */
interface LoginThrottleInterface
{
    /**
     * Throw when these credentials are locked out for the current client.
     *
     * @param array<string, mixed> $credentials
     *
     * @throws TooManyLoginAttemptsException
     */
    public function ensureNotLockedOut(
        string $guard,
        array $credentials,
    ): void;

    /**
     * Count a failed attempt, starting a lockout once the limit is reached.
     *
     * @param array<string, mixed> $credentials
     */
    public function recordFailure(
        string $guard,
        array $credentials,
    ): void;

    /**
     * Forget the failures and lockouts recorded for these credentials and client.
     *
     * @param array<string, mixed> $credentials
     */
    public function clear(
        string $guard,
        array $credentials,
    ): void;
}
