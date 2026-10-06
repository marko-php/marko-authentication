<?php

declare(strict_types=1);

use Marko\Authentication\AuthManager;
use Marko\Authentication\Config\AuthConfig;
use Marko\Authentication\Contracts\GuardInterface;
use Marko\Authentication\Contracts\UserProviderInterface;
use Marko\Authentication\Exceptions\AuthException;
use Marko\Authentication\Guard\GuardDriverRegistry;
use Marko\Authentication\Guard\SessionGuard;
use Marko\Authentication\Token\RememberTokenManager;
use Marko\Testing\Fake\FakeConfigRepository;
use Marko\Testing\Fake\FakeCookieJar;
use Marko\Testing\Fake\FakeEventDispatcher;
use Marko\Testing\Fake\FakeGuard;
use Marko\Testing\Fake\FakeSession;
use Marko\Testing\Fake\FakeUserProvider;

/**
 * @param array<string, array<string, mixed>> $guards
 */
function managerWithDrivers(
    GuardDriverRegistry $guardDriverRegistry,
    array $guards,
    ?UserProviderInterface $provider = null,
): AuthManager {
    $session = new FakeSession();
    $session->start();

    return new AuthManager(
        config: new AuthConfig(new FakeConfigRepository([
            'authentication.remember.cookie.prefix' => 'remember_',
            'authentication.default.guard' => array_key_first($guards),
            'authentication.guards' => $guards,
        ])),
        session: $session,
        provider: $provider ?? new FakeUserProvider(),
        eventDispatcher: new FakeEventDispatcher(),
        cookieJar: new FakeCookieJar(),
        rememberTokenManager: new RememberTokenManager(),
        guardDriverRegistry: $guardDriverRegistry,
    );
}

describe('GuardDriverRegistry', function (): void {
    it('builds guards for a custom driver registered with extend', function (): void {
        $registry = new GuardDriverRegistry();
        $registry->extend('custom', fn (string $name): GuardInterface => new FakeGuard(name: $name));

        $guard = managerWithDrivers($registry, ['partner' => ['driver' => 'custom']])->guard('partner');

        expect($guard)->toBeInstanceOf(FakeGuard::class)
            ->and($guard->getName())->toBe('partner')
            ->and($registry->has('custom'))->toBeTrue()
            ->and($registry->drivers())->toBe(['custom']);
    });

    it('passes the guard name, guard config and user provider to the driver factory', function (): void {
        $provider = new FakeUserProvider();
        $received = [];
        $registry = new GuardDriverRegistry();
        $registry->extend(
            'custom',
            function (string $name, array $config, UserProviderInterface $provider) use (&$received): GuardInterface {
                $received = [$name, $config, $provider];

                return new FakeGuard(name: $name);
            },
        );

        managerWithDrivers(
            $registry,
            ['partner' => ['driver' => 'custom', 'provider' => 'users', 'header' => 'X-Key']],
            $provider,
        )->guard('partner');

        expect($received[0])->toBe('partner')
            ->and($received[1])->toBe(['driver' => 'custom', 'provider' => 'users', 'header' => 'X-Key'])
            ->and($received[2])->toBe($provider);
    });

    it('lets a registered driver replace the built-in session driver', function (): void {
        $registry = new GuardDriverRegistry();
        $registry->extend('session', fn (string $name): GuardInterface => new FakeGuard(name: $name));

        $guard = managerWithDrivers($registry, ['web' => ['driver' => 'session']])->guard('web');

        expect($guard)->toBeInstanceOf(FakeGuard::class)
            ->and($guard)->not->toBeInstanceOf(SessionGuard::class);
    });

    it('builds the built-in session guard when no session driver is registered', function (): void {
        $guard = managerWithDrivers(new GuardDriverRegistry(), ['web' => ['driver' => 'session']])->guard('web');

        expect($guard)->toBeInstanceOf(SessionGuard::class);
    });

    it('throws an error naming marko/authentication-token when the token driver is not registered', function (): void {
        $manager = managerWithDrivers(new GuardDriverRegistry(), ['api' => ['driver' => 'token']]);

        try {
            $manager->guard('api');
            $this->fail('Expected AuthException');
        } catch (AuthException $exception) {
            expect($exception->getMessage())->toContain("Guard 'api' uses the 'token' driver")
                ->and($exception->getSuggestion())->toContain('composer require marko/authentication-token');
        }
    });

    it('lists registered drivers when the guard driver is unknown', function (): void {
        $registry = new GuardDriverRegistry();
        $registry->extend('custom', fn (string $name): GuardInterface => new FakeGuard(name: $name));
        $manager = managerWithDrivers($registry, ['odd' => ['driver' => 'unknown_driver']]);

        try {
            $manager->guard('odd');
            $this->fail('Expected AuthException');
        } catch (AuthException $exception) {
            expect($exception->getMessage())->toContain("Unknown guard driver 'unknown_driver'")
                ->and($exception->getContext())->toContain('session, custom')
                ->and($exception->getSuggestion())->toContain('GuardDriverRegistry::extend()');
        }
    });

    it('throws when a driver factory returns a guard for another name', function (): void {
        $registry = new GuardDriverRegistry();
        $registry->extend('custom', fn (): GuardInterface => new FakeGuard(name: 'other'));

        expect(fn () => managerWithDrivers($registry, ['partner' => ['driver' => 'custom']])->guard('partner'))
            ->toThrow(AuthException::class, "returned a guard named 'other'");
    });
});
