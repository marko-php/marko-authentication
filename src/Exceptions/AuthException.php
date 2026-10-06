<?php

declare(strict_types=1);

namespace Marko\Authentication\Exceptions;

use Exception;
use Throwable;

class AuthException extends Exception
{
    public function __construct(
        string $message,
        private readonly string $context = '',
        private readonly string $suggestion = '',
        int $code = 0,
        ?Throwable $previous = null,
    ) {
        parent::__construct(
            $message,
            $code,
            $previous,
        );
    }

    public static function cookieOutsideRequest(
        string $name,
    ): self {
        return new self(
            message: "Cannot queue cookie '$name': no HTTP request is being handled",
            context: 'RequestCookieJar only writes cookies while QueuedCookiesMiddleware is handling a request',
            suggestion: 'Log users in with remember-me (or log them out) from an HTTP request, and make sure marko/authentication\'s QueuedCookiesMiddleware is in the global middleware stack',
        );
    }

    public static function rememberMeUnavailable(
        string $guard,
    ): self {
        return new self(
            message: "Remember-me was requested on guard '$guard', but the guard has no cookie jar or remember token manager",
            context: "SessionGuard '$guard' was constructed without a CookieJarInterface or RememberTokenManager",
            suggestion: 'Resolve the guard through AuthManager (or GuardInterface), or pass cookieJar and tokenManager when constructing SessionGuard yourself',
        );
    }

    public static function rememberTokenNotStored(
        string $guard,
        string $provider,
    ): self {
        return new self(
            message: "Remember-me was requested on guard '$guard', but the user provider did not store the remember token",
            context: "After $provider::updateRememberToken(), the user's getRememberToken() did not return the new token hash",
            suggestion: 'Make updateRememberToken() call $user->setRememberToken($token) and persist it (e.g. a remember_token column), or log in without remember: true',
        );
    }

    public static function tokenDriverNotInstalled(
        string $guard,
    ): self {
        return new self(
            message: "Guard '$guard' uses the 'token' driver, but no token guard driver is installed",
            context: "No factory is registered for the 'token' driver in GuardDriverRegistry",
            suggestion: "Install the token guard with 'composer require marko/authentication-token', or register your own 'token' driver with GuardDriverRegistry::extend()",
        );
    }

    /**
     * @param list<string> $availableDrivers
     */
    public static function unknownGuardDriver(
        string $guard,
        string $driver,
        array $availableDrivers,
    ): self {
        $available = implode(', ', $availableDrivers);

        return new self(
            message: "Unknown guard driver '$driver'",
            context: "Guard '$guard' is configured with driver '$driver'. Available drivers: $available",
            suggestion: "Use one of the available drivers in authentication.guards.$guard.driver, or register '$driver' with GuardDriverRegistry::extend() from a module.php boot callback",
        );
    }

    public static function guardNameMismatch(
        string $guard,
        string $driver,
        string $returnedName,
    ): self {
        return new self(
            message: "The '$driver' guard driver returned a guard named '$returnedName' for guard '$guard'",
            context: "AuthManager asked the '$driver' driver factory for guard '$guard'",
            suggestion: 'Pass the $name argument the driver factory receives to the guard it builds, so getName() returns the configured guard name',
        );
    }

    public function getContext(): string
    {
        return $this->context;
    }

    public function getSuggestion(): string
    {
        return $this->suggestion;
    }
}
