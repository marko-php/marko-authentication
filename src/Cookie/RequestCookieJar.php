<?php

declare(strict_types=1);

namespace Marko\Authentication\Cookie;

use Marko\Authentication\Config\AuthConfig;
use Marko\Authentication\Contracts\CookieJarInterface;
use Marko\Authentication\Exceptions\AuthException;
use Marko\Config\Exceptions\ConfigNotFoundException;
use Marko\Core\Contracts\ResettableInterface;
use Marko\Routing\Exceptions\CookieException;
use Marko\Routing\Http\Cookie;
use Marko\Routing\Http\Request;
use Override;
use Psr\Clock\ClockInterface;

/**
 * Cookie jar backed by the current HTTP request.
 *
 * Reads come from the inbound request's cookies. Writes and deletes are
 * queued as Cookie objects (a delete is an expired cookie) and attached to
 * the response by QueuedCookiesMiddleware, so cookies always go out through
 * Response::withCookie() and never through setcookie().
 */
class RequestCookieJar implements CookieJarInterface, ResettableInterface
{
    private const int SECONDS_PER_MINUTE = 60;

    private const int EXPIRED_COOKIE_OFFSET_SECONDS = 42000;

    private ?Request $request = null;

    /** @var array<string, Cookie> */
    private array $queued = [];

    /** @var array<string, ?string> Values written during this request, null when deleted */
    private array $queuedValues = [];

    public function __construct(
        private readonly AuthConfig $config,
        private readonly ClockInterface $clock,
    ) {}

    /**
     * Hand the inbound request to the jar. Called by QueuedCookiesMiddleware.
     */
    public function setRequest(
        Request $request,
    ): void {
        $this->request = $request;
    }

    public function get(
        string $name,
    ): ?string {
        if (array_key_exists($name, $this->queuedValues)) {
            return $this->queuedValues[$name];
        }

        $value = $this->request?->cookie($name);

        return is_string($value) ? $value : null;
    }

    /**
     * @throws AuthException|ConfigNotFoundException|CookieException
     */
    public function set(
        string $name,
        string $value,
        int $minutes = 0,
    ): void {
        $this->queue(
            name: $name,
            value: $value,
            expires: $minutes > 0 ? $this->clock->now()->getTimestamp() + $minutes * self::SECONDS_PER_MINUTE : null,
        );
        $this->queuedValues[$name] = $value;
    }

    /**
     * @throws AuthException|ConfigNotFoundException|CookieException
     */
    public function delete(
        string $name,
    ): void {
        $this->queue(
            name: $name,
            value: '',
            expires: $this->clock->now()->getTimestamp() - self::EXPIRED_COOKIE_OFFSET_SECONDS,
        );
        $this->queuedValues[$name] = null;
    }

    /**
     * Return every queued cookie and empty the queue.
     *
     * @return array<int, Cookie>
     */
    public function pullQueuedCookies(): array
    {
        $cookies = array_values($this->queued);
        $this->queued = [];

        return $cookies;
    }

    #[Override]
    public function reset(): void
    {
        $this->request = null;
        $this->queued = [];
        $this->queuedValues = [];
    }

    /**
     * @throws AuthException|ConfigNotFoundException|CookieException
     */
    private function queue(
        string $name,
        string $value,
        ?int $expires,
    ): void {
        if ($this->request === null) {
            throw AuthException::cookieOutsideRequest($name);
        }

        $this->queued[$name] = new Cookie(
            name: $name,
            value: $value,
            expires: $expires,
            path: $this->config->rememberCookiePath(),
            domain: $this->config->rememberCookieDomain(),
            secure: $this->config->rememberCookieSecure(),
            httpOnly: $this->config->rememberCookieHttpOnly(),
            sameSite: $this->config->rememberCookieSameSite(),
        );
    }
}
