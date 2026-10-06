<?php

declare(strict_types=1);

use Marko\Authentication\Config\AuthConfig;
use Marko\Authentication\Contracts\CookieJarInterface;
use Marko\Authentication\Cookie\RequestCookieJar;
use Marko\Authentication\Exceptions\AuthException;
use Marko\Core\Contracts\ResettableInterface;
use Marko\Routing\Http\Request;
use Marko\Testing\Fake\FakeClock;
use Marko\Testing\Fake\FakeConfigRepository;

function createRequestCookieJar(
    array $overrides = [],
    ?FakeClock $clock = null,
): RequestCookieJar {
    return new RequestCookieJar(new AuthConfig(new FakeConfigRepository([
        'authentication.remember.cookie.path' => '/',
        'authentication.remember.cookie.domain' => '',
        'authentication.remember.cookie.secure' => true,
        'authentication.remember.cookie.http_only' => true,
        'authentication.remember.cookie.same_site' => 'Lax',
        ...$overrides,
    ])), $clock ?? new FakeClock());
}

describe('RequestCookieJar', function (): void {
    it('implements CookieJarInterface and ResettableInterface', function (): void {
        expect(createRequestCookieJar())
            ->toBeInstanceOf(CookieJarInterface::class)
            ->toBeInstanceOf(ResettableInterface::class);
    });

    it('reads cookie values from the current request', function (): void {
        $jar = createRequestCookieJar();
        $jar->setRequest(new Request(cookies: ['remember_web' => '42|token']));

        expect($jar->get('remember_web'))->toBe('42|token')
            ->and($jar->get('missing'))->toBeNull();
    });

    it('returns null for cookies before a request is received', function (): void {
        expect(createRequestCookieJar()->get('remember_web'))->toBeNull();
    });

    it('queues a cookie with configured attributes and expiry', function (): void {
        $jar = createRequestCookieJar(['authentication.remember.cookie.domain' => 'example.com']);
        $jar->setRequest(new Request());

        $jar->set('remember_web', '42|token', 60);

        $cookies = $jar->pullQueuedCookies();
        $header = $cookies[0]->toSetCookieString();

        expect($cookies)->toHaveCount(1)
            ->and($header)->toStartWith('remember_web=42%7Ctoken')
            ->toContain('Path=/')
            ->toContain('Domain=example.com')
            ->toContain('Secure')
            ->toContain('HttpOnly')
            ->toContain('SameSite=Lax')
            ->toContain('Expires=');
    });

    it('sets the cookie expiry relative to the injected clock', function (): void {
        $clock = new FakeClock('2026-01-01 12:00:00 UTC');
        $jar = createRequestCookieJar(clock: $clock);
        $jar->setRequest(new Request());

        $jar->set('remember_web', '42|token', 60);

        expect($jar->pullQueuedCookies()[0]->expires())
            ->toBe($clock->now()->getTimestamp() + 3600);
    });

    it('expires a deleted cookie relative to the injected clock', function (): void {
        $clock = new FakeClock('2026-01-01 12:00:00 UTC');
        $jar = createRequestCookieJar(clock: $clock);
        $jar->setRequest(new Request());

        $jar->delete('remember_web');

        expect($jar->pullQueuedCookies()[0]->expires())
            ->toBe($clock->now()->getTimestamp() - 42000);
    });

    it('queues a session cookie when minutes is zero', function (): void {
        $jar = createRequestCookieJar();
        $jar->setRequest(new Request());

        $jar->set('remember_web', 'value');

        expect($jar->pullQueuedCookies()[0]->toSetCookieString())->not->toContain('Expires=');
    });

    it('serves a queued value to later reads in the same request', function (): void {
        $jar = createRequestCookieJar();
        $jar->setRequest(new Request(cookies: ['remember_web' => 'old']));

        $jar->set('remember_web', 'new', 60);

        expect($jar->get('remember_web'))->toBe('new');

        $jar->delete('remember_web');

        expect($jar->get('remember_web'))->toBeNull();
    });

    it('queues an expired cookie on delete', function (): void {
        $jar = createRequestCookieJar();
        $jar->setRequest(new Request(cookies: ['remember_web' => '42|token']));

        $jar->delete('remember_web');

        $header = $jar->pullQueuedCookies()[0]->toSetCookieString();
        $expires = strtotime(substr($header, strpos($header, 'Expires=') + 8, 29));

        expect($header)->toStartWith('remember_web=;')
            ->toContain('Path=/')
            ->and($expires)->toBeLessThan(time());
    });

    it('replaces an earlier queued cookie with the same name', function (): void {
        $jar = createRequestCookieJar();
        $jar->setRequest(new Request());

        $jar->set('remember_web', 'first', 60);
        $jar->delete('remember_web');

        $cookies = $jar->pullQueuedCookies();

        expect($cookies)->toHaveCount(1)
            ->and($cookies[0]->toSetCookieString())->toStartWith('remember_web=;');
    });

    it('empties the queue when cookies are pulled', function (): void {
        $jar = createRequestCookieJar();
        $jar->setRequest(new Request());
        $jar->set('remember_web', 'value', 60);

        $jar->pullQueuedCookies();

        expect($jar->pullQueuedCookies())->toBeEmpty();
    });

    it('throws when writing a cookie outside an http request', function (): void {
        $jar = createRequestCookieJar();

        expect(fn () => $jar->set('remember_web', 'value', 60))
            ->toThrow(AuthException::class, 'Cannot queue cookie')
            ->and(fn () => $jar->delete('remember_web'))
            ->toThrow(AuthException::class, 'Cannot queue cookie');
    });

    it('clears the request and queued cookies on reset', function (): void {
        $jar = createRequestCookieJar();
        $jar->setRequest(new Request(cookies: ['remember_web' => '42|token']));
        $jar->set('other', 'value', 60);

        $jar->reset();

        expect($jar->get('remember_web'))->toBeNull()
            ->and($jar->get('other'))->toBeNull()
            ->and($jar->pullQueuedCookies())->toBeEmpty()
            ->and(fn () => $jar->set('other', 'value', 60))->toThrow(AuthException::class);
    });
});
