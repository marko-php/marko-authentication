<?php

declare(strict_types=1);

namespace Marko\Authentication\Exceptions;

use Marko\Core\Exceptions\HttpExceptionInterface;

/**
 * Login attempts for these credentials are locked out for this client.
 *
 * Rendered as 429 Too Many Requests with a Retry-After header by the routing
 * pipeline wherever it is thrown; catch it to render your own login page.
 */
class TooManyLoginAttemptsException extends AuthException implements HttpExceptionInterface
{
    private int $retryAfter = 1;

    public static function lockedOut(
        string $guard,
        int $retryAfter,
    ): self {
        $exception = new self(
            message: 'Too many login attempts. Please try again later.',
            context: "Login attempts on guard '$guard' for these credentials are locked out for this client for $retryAfter more seconds",
            suggestion: 'Wait until the lockout ends, or tune authentication.throttle (max_attempts, decay_seconds, lockout_seconds, max_lockout_seconds)',
        );
        $exception->retryAfter = max(1, $retryAfter);

        return $exception;
    }

    /**
     * Seconds until the client may try again.
     */
    public function getRetryAfter(): int
    {
        return $this->retryAfter;
    }

    public function getStatusCode(): int
    {
        return 429;
    }

    /**
     * @return array<string, string>
     */
    public function getHeaders(): array
    {
        return ['Retry-After' => (string) $this->retryAfter];
    }

    /**
     * @return array<string, mixed>
     */
    public function getResponseData(): array
    {
        return [
            'message' => $this->getMessage(),
            'retry_after' => $this->retryAfter,
        ];
    }
}
