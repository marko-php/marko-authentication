<?php

declare(strict_types=1);

namespace Marko\Authentication\Tests\Unit\Guard;

use Marko\Authentication\AuthenticatableInterface;
use Marko\Authentication\Contracts\CookieJarInterface;
use Marko\Authentication\Contracts\UserProviderInterface;
use Marko\Authentication\Exceptions\AuthException;
use Marko\Authentication\Guard\SessionGuard;
use Marko\Authentication\Token\RememberTokenManager;
use Marko\Testing\Fake\FakeAuthenticatable;
use Marko\Testing\Fake\FakeCookieJar;
use Marko\Testing\Fake\FakeSession;
use Marko\Testing\Fake\FakeUserProvider;

function startedRememberSession(): FakeSession
{
    $session = new FakeSession();
    $session->start();

    return $session;
}

describe('SessionGuard remember-me', function (): void {
    it('throws AuthException when remember is requested without a cookie jar or token manager', function (): void {
        $user = new FakeAuthenticatable(id: 42);
        $guard = new SessionGuard(
            session: startedRememberSession(),
            provider: new FakeUserProvider([42 => $user]),
            name: 'web',
        );

        expect(fn () => $guard->login($user, remember: true))
            ->toThrow(AuthException::class, "Remember-me was requested on guard 'web'");
    });

    it('throws AuthException when the user provider does not store the remember token', function (): void {
        $user = new FakeAuthenticatable(id: 42);
        $provider = new readonly class () implements UserProviderInterface
        {
            public function retrieveById(int|string $identifier): ?AuthenticatableInterface
            {
                return null;
            }

            public function retrieveByCredentials(array $credentials): ?AuthenticatableInterface
            {
                return null;
            }

            public function validateCredentials(
                AuthenticatableInterface $user,
                array $credentials,
            ): bool {
                return false;
            }

            public function retrieveByRememberToken(
                int|string $identifier,
                string $token,
            ): ?AuthenticatableInterface {
                return null;
            }

            public function updateRememberToken(
                AuthenticatableInterface $user,
                ?string $token,
            ): void {}
        };
        $guard = new SessionGuard(
            session: startedRememberSession(),
            provider: $provider,
            name: 'web',
            cookieJar: new FakeCookieJar(),
            tokenManager: new RememberTokenManager(),
        );

        expect(fn () => $guard->login($user, remember: true))
            ->toThrow(AuthException::class, 'did not store the remember token');
    });

    it('looks up remember users by the hashed token', function (): void {
        $tokenManager = new RememberTokenManager();
        $user = new FakeAuthenticatable(id: 42);
        $user->setRememberToken($tokenManager->hash('plain-token'));
        $cookieJar = new FakeCookieJar();
        $cookieJar->set('remember_web', '42|plain-token');
        $provider = new FakeUserProvider([42 => $user]);

        $guard = new SessionGuard(
            session: startedRememberSession(),
            provider: $provider,
            name: 'web',
            cookieJar: $cookieJar,
            tokenManager: $tokenManager,
        );

        expect($guard->user())->toBe($user)
            ->and($provider->lastRememberTokenUpdate['token'])->not->toBe($tokenManager->hash('plain-token'));
    });

    it('authenticates via remember cookie set by a previous login with FakeUserProvider', function (): void {
        $user = new FakeAuthenticatable(id: 42);
        $provider = new FakeUserProvider([42 => $user]);
        $tokenManager = new RememberTokenManager();
        $cookieJar = new FakeCookieJar();

        $first = new SessionGuard(
            session: startedRememberSession(),
            provider: $provider,
            name: 'web',
            cookieJar: $cookieJar,
            tokenManager: $tokenManager,
        );
        $first->login($user, remember: true);

        $second = new SessionGuard(
            session: startedRememberSession(),
            provider: $provider,
            name: 'web',
            cookieJar: $cookieJar,
            tokenManager: $tokenManager,
        );

        expect($second->user())->toBe($user);
    });

    it('rejects a remember cookie whose token does not match', function (): void {
        $tokenManager = new RememberTokenManager();
        $user = new FakeAuthenticatable(id: 42);
        $user->setRememberToken($tokenManager->hash('real-token'));
        $cookieJar = new FakeCookieJar();
        $cookieJar->set('remember_web', '42|forged-token');

        $guard = new SessionGuard(
            session: startedRememberSession(),
            provider: new FakeUserProvider([42 => $user]),
            name: 'web',
            cookieJar: $cookieJar,
            tokenManager: $tokenManager,
        );

        expect($guard->user())->toBeNull();
    });

    it('sets the remember cookie for the token manager lifetime', function (): void {
        $user = new FakeAuthenticatable(id: 42);
        $cookieJar = new class () implements CookieJarInterface
        {
            public ?int $minutes = null;

            public function get(string $name): ?string
            {
                return null;
            }

            public function set(
                string $name,
                string $value,
                int $minutes = 0,
            ): void {
                $this->minutes = $minutes;
            }

            public function delete(string $name): void {}
        };

        $guard = new SessionGuard(
            session: startedRememberSession(),
            provider: new FakeUserProvider([42 => $user]),
            name: 'web',
            cookieJar: $cookieJar,
            tokenManager: new RememberTokenManager(lifetimeMinutes: 90),
        );
        $guard->login($user, remember: true);

        expect($cookieJar->minutes)->toBe(90);
    });

    it('names the remember cookie with the configured prefix', function (): void {
        $user = new FakeAuthenticatable(id: 42);
        $cookieJar = new FakeCookieJar();

        $guard = new SessionGuard(
            session: startedRememberSession(),
            provider: new FakeUserProvider([42 => $user]),
            name: 'web',
            cookieJar: $cookieJar,
            tokenManager: new RememberTokenManager(),
            rememberCookiePrefix: 'keep_',
        );
        $guard->login($user, remember: true);

        expect($cookieJar->cookies)->toHaveKey('keep_web')
            ->not->toHaveKey('remember_web');
    });
});
