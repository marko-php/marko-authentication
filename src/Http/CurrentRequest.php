<?php

declare(strict_types=1);

namespace Marko\Authentication\Http;

use Marko\Core\Contracts\ResettableInterface;
use Marko\Routing\Http\Request;
use Override;

/**
 * Holds the HTTP request being handled, so the login throttle can key failed
 * attempts by client IP. The Request is not a container service, so
 * QueuedCookiesMiddleware (global middleware) sets it here for each request.
 * Outside a request (CLI, queue jobs) it holds nothing.
 */
class CurrentRequest implements ResettableInterface
{
    private ?Request $request = null;

    public function set(
        Request $request,
    ): void {
        $this->request = $request;
    }

    public function get(): ?Request
    {
        return $this->request;
    }

    #[Override]
    public function reset(): void
    {
        $this->request = null;
    }
}
