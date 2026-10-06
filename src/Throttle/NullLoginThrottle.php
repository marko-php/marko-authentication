<?php

declare(strict_types=1);

namespace Marko\Authentication\Throttle;

use Marko\Authentication\Contracts\LoginThrottleInterface;

/**
 * Bound when authentication.throttle.enabled is false: login attempts are not
 * throttled. Use it when the app throttles logins itself, for example from a
 * FailedLoginEvent observer or a reverse proxy.
 */
readonly class NullLoginThrottle implements LoginThrottleInterface
{
    public function ensureNotLockedOut(
        string $guard,
        array $credentials,
    ): void {}

    public function recordFailure(
        string $guard,
        array $credentials,
    ): void {}

    public function clear(
        string $guard,
        array $credentials,
    ): void {}
}
