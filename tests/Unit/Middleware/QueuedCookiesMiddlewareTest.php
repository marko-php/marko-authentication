<?php

declare(strict_types=1);

use Marko\Authentication\Config\AuthConfig;
use Marko\Authentication\Cookie\RequestCookieJar;
use Marko\Authentication\Http\CurrentRequest;
use Marko\Authentication\Middleware\QueuedCookiesMiddleware;
use Marko\Routing\Attributes\RunsOnUnmatched;
use Marko\Routing\Http\Request;
use Marko\Routing\Http\Response;
use Marko\Routing\Middleware\MiddlewareInterface;
use Marko\Testing\Fake\FakeClock;
use Marko\Testing\Fake\FakeConfigRepository;

function createQueuedCookiesJar(): RequestCookieJar
{
    return new RequestCookieJar(new AuthConfig(new FakeConfigRepository([
        'authentication.remember.cookie.path' => '/',
        'authentication.remember.cookie.domain' => '',
        'authentication.remember.cookie.secure' => false,
        'authentication.remember.cookie.http_only' => true,
        'authentication.remember.cookie.same_site' => 'Lax',
    ])), new FakeClock());
}

describe('QueuedCookiesMiddleware', function (): void {
    it('implements MiddlewareInterface', function (): void {
        expect(new QueuedCookiesMiddleware(createQueuedCookiesJar(), new CurrentRequest()))->toBeInstanceOf(
            MiddlewareInterface::class,
        );
    });

    it('gives the inbound request to the cookie jar before the handler runs', function (): void {
        $jar = createQueuedCookiesJar();
        $middleware = new QueuedCookiesMiddleware($jar, new CurrentRequest());
        $seen = null;

        $middleware->handle(
            new Request(cookies: ['remember_web' => '42|token']),
            function (Request $request) use ($jar, &$seen): Response {
                $seen = $jar->get('remember_web');

                return new Response('ok');
            },
        );

        expect($seen)->toBe('42|token');
    });

    it('gives the inbound request to CurrentRequest for the login throttle', function (): void {
        $currentRequest = new CurrentRequest();
        $middleware = new QueuedCookiesMiddleware(createQueuedCookiesJar(), $currentRequest);
        $request = new Request(server: ['REMOTE_ADDR' => '203.0.113.7']);
        $seen = null;

        $middleware->handle(
            $request,
            function () use ($currentRequest, &$seen): Response {
                $seen = $currentRequest->get();

                return new Response('ok');
            },
        );

        expect($seen)->toBe($request);
    });

    it('attaches queued cookies to the response', function (): void {
        $jar = createQueuedCookiesJar();
        $middleware = new QueuedCookiesMiddleware($jar, new CurrentRequest());

        $response = $middleware->handle(
            new Request(),
            function () use ($jar): Response {
                $jar->set('remember_web', '42|token', 60);
                $jar->delete('stale');

                return new Response('ok');
            },
        );

        $names = array_map(fn ($cookie): string => $cookie->name(), $response->cookies());

        expect($names)->toBe(['remember_web', 'stale'])
            ->and($response->body())->toBe('ok');
    });

    it('returns the response untouched when nothing is queued', function (): void {
        $middleware = new QueuedCookiesMiddleware(createQueuedCookiesJar(), new CurrentRequest());
        $original = new Response('ok');

        $response = $middleware->handle(new Request(), fn (): Response => $original);

        expect($response)->toBe($original);
    });

    it('flushes the queue after attaching cookies', function (): void {
        $jar = createQueuedCookiesJar();
        $middleware = new QueuedCookiesMiddleware($jar, new CurrentRequest());

        $middleware->handle(
            new Request(),
            function () use ($jar): Response {
                $jar->set('remember_web', '42|token', 60);

                return new Response('ok');
            },
        );

        expect($jar->pullQueuedCookies())->toBeEmpty();
    });
});

it('does not run on unmatched requests, where nothing can queue a cookie', function (): void {
    $attributes = new ReflectionClass(QueuedCookiesMiddleware::class)->getAttributes(RunsOnUnmatched::class);

    expect($attributes)->toBe([]);
})->issue(267);
