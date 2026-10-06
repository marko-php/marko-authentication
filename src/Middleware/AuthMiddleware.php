<?php

declare(strict_types=1);

namespace Marko\Authentication\Middleware;

use Marko\Authentication\AuthManager;
use Marko\Authentication\Exceptions\AuthException;
use Marko\Authentication\Guard\TokenGuard;
use Marko\Config\Exceptions\ConfigNotFoundException;
use Marko\Routing\Exceptions\HttpException;
use Marko\Routing\Http\Request;
use Marko\Routing\Http\Response;
use Marko\Routing\Middleware\MiddlewareInterface;

/**
 * Lets authenticated requests through.
 *
 * An unauthenticated request is redirected to `redirectTo` when one is set
 * and the guard is stateful. Otherwise (and always for token guards, whose
 * clients cannot follow a login redirect) it throws a 401 HttpException,
 * which the routing pipeline renders through ExceptionRenderer as JSON or
 * HTML according to the request's Accept header.
 */
readonly class AuthMiddleware implements MiddlewareInterface
{
    public function __construct(
        private AuthManager $auth,
        private ?string $guard = null,
        private ?string $redirectTo = '/login',
    ) {}

    /**
     * @throws AuthException|ConfigNotFoundException|HttpException
     */
    public function handle(
        Request $request,
        callable $next,
    ): Response {
        $guard = $this->auth->guard($this->guard);

        if ($guard->check()) {
            return $next($request);
        }

        if ($this->redirectTo !== null && !$guard instanceof TokenGuard) {
            return Response::redirect($this->redirectTo);
        }

        throw HttpException::unauthorized('Unauthorized.');
    }
}
