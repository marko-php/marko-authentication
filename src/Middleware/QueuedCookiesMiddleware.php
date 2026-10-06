<?php

declare(strict_types=1);

namespace Marko\Authentication\Middleware;

use Marko\Authentication\Cookie\RequestCookieJar;
use Marko\Authentication\Http\CurrentRequest;
use Marko\Routing\Http\Request;
use Marko\Routing\Http\Response;
use Marko\Routing\Middleware\MiddlewareInterface;

/**
 * Hands the inbound request to the RequestCookieJar and to CurrentRequest
 * (read by the login throttle), then attaches every
 * cookie queued during the request (remember-me cookies, expired cookies
 * from logout) to the outgoing response via Response::withCookie().
 */
readonly class QueuedCookiesMiddleware implements MiddlewareInterface
{
    public function __construct(
        private RequestCookieJar $requestCookieJar,
        private CurrentRequest $currentRequest,
    ) {}

    public function handle(
        Request $request,
        callable $next,
    ): Response {
        $this->requestCookieJar->setRequest($request);
        $this->currentRequest->set($request);

        $response = $next($request);

        foreach ($this->requestCookieJar->pullQueuedCookies() as $cookie) {
            $response = $response->withCookie($cookie);
        }

        return $response;
    }
}
