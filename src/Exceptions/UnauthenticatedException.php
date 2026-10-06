<?php

declare(strict_types=1);

namespace Marko\Authentication\Exceptions;

use Marko\Authentication\Contracts\GuardInterface;
use Marko\Authentication\Contracts\StatelessGuardInterface;
use Marko\Routing\Exceptions\HttpException;

/**
 * The framework's 401 for a request with no authenticated user.
 *
 * Every middleware that turns a guest away with a 401 (AuthMiddleware,
 * AuthorizationMiddleware for #[Can], AdminAuthMiddleware) builds it here, so
 * the response looks the same whichever one protects the route. A stateless
 * guard's 401 carries its WWW-Authenticate challenge (RFC 9110 §15.5.2), which
 * API clients read to know they must re-authenticate.
 */
class UnauthenticatedException extends HttpException
{
    public static function forGuard(
        GuardInterface $guard,
    ): self {
        $headers = $guard instanceof StatelessGuardInterface
            ? ['WWW-Authenticate' => $guard->getChallenge()]
            : [];

        return new self(
            statusCode: 401,
            message: 'Unauthorized.',
            headers: $headers,
            context: "No authenticated user on guard '{$guard->getName()}'",
            suggestion: 'Send the credentials the guard expects (a session login, or a valid Authorization header for a token guard)',
        );
    }
}
