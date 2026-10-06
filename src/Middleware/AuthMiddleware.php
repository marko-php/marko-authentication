<?php

declare(strict_types=1);

namespace Marko\Authentication\Middleware;

use Marko\Authentication\AuthManager;
use Marko\Authentication\Contracts\StatelessGuardInterface;
use Marko\Authentication\Exceptions\AuthException;
use Marko\Config\Exceptions\ConfigNotFoundException;
use Marko\Routing\Exceptions\HttpException;
use Marko\Routing\Http\Request;
use Marko\Routing\Http\Response;
use Marko\Routing\Middleware\MiddlewareInterface;

/**
 * Lets authenticated requests through.
 *
 * An unauthenticated request throws a 401 HttpException, which the routing
 * pipeline renders through ExceptionRenderer as JSON or HTML according to the
 * request's Accept header. The one exception is a browser request on a
 * stateful guard: it is redirected to `redirectTo` when one is set.
 *
 * A stateless guard (StatelessGuardInterface, e.g. the token guard) never
 * redirects, since its API clients cannot follow a login redirect, and its
 * 401 carries the guard's WWW-Authenticate challenge. A request that wants
 * JSON (Request::wantsJson()) never redirects either, whatever the guard.
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

        if ($guard instanceof StatelessGuardInterface) {
            throw new HttpException(
                statusCode: 401,
                message: 'Unauthorized.',
                headers: ['WWW-Authenticate' => $guard->getChallenge()],
            );
        }

        if ($this->redirectTo !== null && !$request->wantsJson()) {
            return Response::redirect($this->redirectTo);
        }

        throw HttpException::unauthorized('Unauthorized.');
    }
}
