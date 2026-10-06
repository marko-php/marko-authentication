<?php

declare(strict_types=1);

namespace Marko\Authentication\Tests\Unit\Guard;

use Marko\Authentication\Event\LoginEvent;
use Marko\Authentication\Guard\SessionGuard;
use Marko\Authentication\Http\CurrentRequest;
use Marko\Authentication\Tests\Fixtures\InMemoryRememberTokenStorage;
use Marko\Authentication\Token\RememberTokenManager;
use Marko\Authentication\Token\RememberTokenRecord;
use Marko\Routing\Http\Request;
use Marko\Testing\Fake\FakeAuthenticatable;
use Marko\Testing\Fake\FakeClock;
use Marko\Testing\Fake\FakeCookieJar;
use Marko\Testing\Fake\FakeEventDispatcher;
use Marko\Testing\Fake\FakeSession;
use Marko\Testing\Fake\FakeUserProvider;

/**
 * One user, per-device token storage, and a clock shared by every device (browser) built with deviceGuard().
 */
class DeviceRememberWorld
{
    public FakeClock $clock;

    public RememberTokenManager $tokenManager;

    public InMemoryRememberTokenStorage $storage;

    public FakeAuthenticatable $user;

    public FakeUserProvider $provider;

    public function __construct()
    {
        $this->clock = new FakeClock('2026-01-01 12:00:00');
        $this->tokenManager = new RememberTokenManager($this->clock, lifetimeMinutes: 60);
        $this->storage = new InMemoryRememberTokenStorage($this->clock);
        $this->user = new FakeAuthenticatable(id: 42);
        $this->provider = new FakeUserProvider([42 => $this->user]);
    }

    /**
     * A guard for a fresh request from the device whose cookies live in $cookieJar (a new session each time).
     */
    public function deviceGuard(
        FakeCookieJar $cookieJar,
        ?FakeEventDispatcher $eventDispatcher = null,
        ?CurrentRequest $currentRequest = null,
    ): SessionGuard {
        $session = new FakeSession();
        $session->start();

        return new SessionGuard(
            session: $session,
            provider: $this->provider,
            name: 'web',
            cookieJar: $cookieJar,
            tokenManager: $this->tokenManager,
            eventDispatcher: $eventDispatcher,
            rememberTokenStorage: $this->storage,
            currentRequest: $currentRequest,
        );
    }

    /**
     * Log the user in with remember-me on a new device and return that device's cookie jar.
     */
    public function rememberedDevice(): FakeCookieJar
    {
        $cookieJar = new FakeCookieJar();
        $this->deviceGuard($cookieJar)->login($this->user, remember: true);

        return $cookieJar;
    }
}

function cookieSelector(
    FakeCookieJar $cookieJar,
): string {
    return explode(':', (string) $cookieJar->get('remember_web'))[0];
}

describe('SessionGuard per-device remember tokens', function (): void {
    it('stores a hashed selector:validator token for the device and leaves the user column alone', function (): void {
        $world = new DeviceRememberWorld();
        $cookieJar = $world->rememberedDevice();

        [$selector, $validator] = explode(':', (string) $cookieJar->get('remember_web'));
        $record = $world->storage->findBySelector('web', $selector);

        expect($record)->toBeInstanceOf(RememberTokenRecord::class)
            ->and($record->userId)->toBe(42)
            ->and($record->validatorHash)->toBe($world->tokenManager->hash($validator))
            ->and($record->validatorHash)->not->toBe($validator)
            ->and($record->expiresAt)->toEqual($world->clock->now()->modify('+60 minutes'))
            ->and($world->provider->lastRememberTokenUpdate)->toBeNull()
            ->and($world->user->getRememberToken())->toBeNull();
    });

    it('keeps two devices logged in independently', function (): void {
        $world = new DeviceRememberWorld();
        $laptop = $world->rememberedDevice();
        $phone = $world->rememberedDevice();

        // Each device comes back several times; every remember-me login rotates only its own token
        foreach (range(1, 3) as $visit) {
            expect($world->deviceGuard($laptop)->user())->toBe($world->user)
                ->and($world->deviceGuard($phone)->user())->toBe($world->user);
        }

        expect($world->storage->tokensFor('web', 42))->toHaveCount(2);
    });

    it('does not log one device out when another device logs in with remember-me', function (): void {
        $world = new DeviceRememberWorld();
        $laptop = $world->rememberedDevice();

        $world->rememberedDevice();
        $world->rememberedDevice();

        expect($world->deviceGuard($laptop)->user())->toBe($world->user);
    });

    it('rotates only the validator, keeping the selector and the original expiry', function (): void {
        $world = new DeviceRememberWorld();
        $cookieJar = $world->rememberedDevice();
        $original = (string) $cookieJar->get('remember_web');
        $selector = cookieSelector($cookieJar);
        $expiresAt = $world->storage->findBySelector('web', $selector)->expiresAt;

        $world->clock->travel('+20 minutes');
        $world->deviceGuard($cookieJar)->user();

        expect($cookieJar->get('remember_web'))->not->toBe($original)
            ->and(cookieSelector($cookieJar))->toBe($selector)
            ->and($world->storage->findBySelector('web', $selector)->expiresAt)->toEqual($expiresAt)
            ->and($world->storage->tokensFor('web', 42))->toHaveCount(1);
    });

    it('rejects a replayed validator once the token has rotated', function (): void {
        $world = new DeviceRememberWorld();
        $cookieJar = $world->rememberedDevice();
        $stolen = new FakeCookieJar();
        $stolen->set('remember_web', (string) $cookieJar->get('remember_web'));

        $world->deviceGuard($cookieJar)->user();

        expect($world->deviceGuard($stolen)->user())->toBeNull();
    });

    it('logs one device out without affecting the other', function (): void {
        $world = new DeviceRememberWorld();
        $laptop = $world->rememberedDevice();
        $phone = $world->rememberedDevice();
        $laptopSelector = cookieSelector($laptop);

        $world->deviceGuard($laptop)->logout();

        expect($laptop->get('remember_web'))->toBeNull()
            ->and($world->storage->findBySelector('web', $laptopSelector))->toBeNull()
            ->and($world->storage->tokensFor('web', 42))->toHaveCount(1)
            ->and($world->deviceGuard($phone)->user())->toBe($world->user);
    });

    it('does not let a planted cookie revoke another user\'s device on logout', function (): void {
        $world = new DeviceRememberWorld();
        $victim = $world->rememberedDevice();
        $intruder = new FakeAuthenticatable(id: 7);
        $world->storage->store(new RememberTokenRecord(
            guard: 'web',
            userId: 7,
            selector: 'intruder-selector',
            validatorHash: $world->tokenManager->hash('intruder-validator'),
            expiresAt: $world->clock->now()->modify('+1 hour'),
        ));
        $intruderJar = new FakeCookieJar();
        $guard = $world->deviceGuard($intruderJar);
        $guard->login($intruder);
        $intruderJar->set('remember_web', cookieSelector($victim) . ':anything');

        $guard->logout();

        expect($world->storage->findBySelector('web', cookieSelector($victim)))->not->toBeNull();
    });

    it('rejects a tampered validator and keeps the device token', function (): void {
        $world = new DeviceRememberWorld();
        $cookieJar = $world->rememberedDevice();
        $selector = cookieSelector($cookieJar);
        $cookieJar->set('remember_web', $selector . ':' . str_repeat('0', 64));

        expect($world->deviceGuard($cookieJar)->user())->toBeNull()
            ->and($world->storage->findBySelector('web', $selector))->not->toBeNull();
    });

    it('rejects malformed cookies', function (string $cookie): void {
        $world = new DeviceRememberWorld();
        $world->rememberedDevice();
        $cookieJar = new FakeCookieJar();
        $cookieJar->set('remember_web', $cookie);

        expect($world->deviceGuard($cookieJar)->user())->toBeNull();
    })->with([
        'no separator' => ['abcdef'],
        'empty selector' => [':validator'],
        'empty validator' => ['selector:'],
    ]);

    it('forgets the cookie of a token that no longer exists', function (): void {
        $world = new DeviceRememberWorld();
        $cookieJar = $world->rememberedDevice();
        $world->storage->clearAllTokens();

        expect($world->deviceGuard($cookieJar)->user())->toBeNull()
            ->and($cookieJar->get('remember_web'))->toBeNull();
    });

    it('rejects an expired device token, deleting its row and cookie', function (): void {
        $world = new DeviceRememberWorld();
        $cookieJar = $world->rememberedDevice();
        $selector = cookieSelector($cookieJar);

        $world->clock->travel('+60 minutes');

        expect($world->deviceGuard($cookieJar)->user())->toBeNull()
            ->and($world->storage->findBySelector('web', $selector))->toBeNull()
            ->and($cookieJar->get('remember_web'))->toBeNull();
    });

    it('deletes the token of a user who no longer exists', function (): void {
        $world = new DeviceRememberWorld();
        $world->storage->store(new RememberTokenRecord(
            guard: 'web',
            userId: 99,
            selector: 'gone-selector',
            validatorHash: $world->tokenManager->hash('gone-validator'),
            expiresAt: $world->clock->now()->modify('+1 hour'),
        ));
        $cookieJar = new FakeCookieJar();
        $cookieJar->set('remember_web', 'gone-selector:gone-validator');

        expect($world->deviceGuard($cookieJar)->user())->toBeNull()
            ->and($world->storage->findBySelector('web', 'gone-selector'))->toBeNull()
            ->and($cookieJar->get('remember_web'))->toBeNull();
    });

    it('logs in only one of two requests racing to rotate the same token', function (): void {
        $world = new DeviceRememberWorld();
        $cookieJar = $world->rememberedDevice();
        $cookie = (string) $cookieJar->get('remember_web');
        $first = new FakeCookieJar();
        $first->set('remember_web', $cookie);
        $second = new FakeCookieJar();
        $second->set('remember_web', $cookie);
        $firstGuard = $world->deviceGuard($first);
        $secondGuard = $world->deviceGuard($second);

        expect($firstGuard->user())->toBe($world->user)
            ->and($secondGuard->user())->toBeNull()
            ->and($world->storage->tokensFor('web', 42))->toHaveCount(1);
    });

    it('only accepts tokens the same guard issued', function (): void {
        $world = new DeviceRememberWorld();
        $cookieJar = $world->rememberedDevice();
        $record = $world->storage->findBySelector('web', cookieSelector($cookieJar));
        $world->storage->clearAllTokens();
        $world->storage->store(new RememberTokenRecord(
            guard: 'admin',
            userId: $record->userId,
            selector: $record->selector,
            validatorHash: $record->validatorHash,
            expiresAt: $record->expiresAt,
        ));

        expect($world->deviceGuard($cookieJar)->user())->toBeNull();
    });

    it('starts a session and dispatches a remembered LoginEvent on a device-token login', function (): void {
        $world = new DeviceRememberWorld();
        $cookieJar = $world->rememberedDevice();
        $events = new FakeEventDispatcher();

        $world->deviceGuard($cookieJar, $events)->user();

        $loginEvents = $events->dispatched(LoginEvent::class);

        expect($loginEvents)->toHaveCount(1)
            ->and($loginEvents[0]->remember)->toBeTrue();
    });

    it('records the device user agent with the token', function (): void {
        $world = new DeviceRememberWorld();
        $currentRequest = new CurrentRequest();
        $currentRequest->set(new Request(server: ['HTTP_USER_AGENT' => 'Firefox on Linux']));
        $cookieJar = new FakeCookieJar();

        $world->deviceGuard($cookieJar, currentRequest: $currentRequest)->login($world->user, remember: true);

        expect($world->storage->findBySelector('web', cookieSelector($cookieJar))->userAgent)
            ->toBe('Firefox on Linux');
    });

    it('moves a single-column id|token cookie onto its own device token', function (): void {
        $world = new DeviceRememberWorld();
        $world->user->setRememberToken($world->tokenManager->hash('legacy-token'));
        $world->user->setRememberTokenExpiresAt($world->clock->now()->modify('+30 minutes'));
        $cookieJar = new FakeCookieJar();
        $cookieJar->set('remember_web', '42|legacy-token');

        expect($world->deviceGuard($cookieJar)->user())->toBe($world->user)
            ->and($world->user->getRememberToken())->toBeNull()
            ->and($cookieJar->get('remember_web'))->toContain(':')
            ->and($world->storage->findBySelector('web', cookieSelector($cookieJar))->expiresAt)
            ->toEqual($world->clock->now()->modify('+30 minutes'))
            ->and($world->deviceGuard($cookieJar)->user())->toBe($world->user);
    });
});
