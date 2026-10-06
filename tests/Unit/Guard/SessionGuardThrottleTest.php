<?php

declare(strict_types=1);

use Marko\Authentication\Contracts\LoginThrottleInterface;
use Marko\Authentication\Exceptions\TooManyLoginAttemptsException;
use Marko\Authentication\Guard\SessionGuard;
use Marko\Testing\Fake\FakeAuthenticatable;
use Marko\Testing\Fake\FakeSession;
use Marko\Testing\Fake\FakeUserProvider;

class RecordingLoginThrottle implements LoginThrottleInterface
{
    /** @var list<string> */
    public array $calls = [];

    public function __construct(
        private readonly bool $lockedOut = false,
    ) {}

    public function ensureNotLockedOut(
        string $guard,
        array $credentials,
    ): void {
        $this->calls[] = "check:$guard";

        if ($this->lockedOut) {
            throw TooManyLoginAttemptsException::lockedOut($guard, 30);
        }
    }

    public function recordFailure(
        string $guard,
        array $credentials,
    ): void {
        $this->calls[] = "failure:$guard";
    }

    public function clear(
        string $guard,
        array $credentials,
    ): void {
        $this->calls[] = "clear:$guard";
    }
}

function createThrottledGuard(
    RecordingLoginThrottle $throttle,
    FakeUserProvider $provider,
): SessionGuard {
    $session = new FakeSession();
    $session->start();

    return new SessionGuard(
        session: $session,
        provider: $provider,
        name: 'web',
        loginThrottle: $throttle,
    );
}

function createPasswordProvider(): FakeUserProvider
{
    return new FakeUserProvider(
        [42 => new FakeAuthenticatable(id: 42)],
        fn ($user, array $credentials): bool => ($credentials['password'] ?? null) === 'secret',
    );
}

describe('SessionGuard login throttling', function (): void {
    it('counts a failure when the password is wrong', function (): void {
        $throttle = new RecordingLoginThrottle();

        $result = createThrottledGuard($throttle, createPasswordProvider())
            ->attempt(['identifier' => 42, 'password' => 'wrong']);

        expect($result)->toBeFalse()
            ->and($throttle->calls)->toBe(['check:web', 'failure:web']);
    });

    it('counts a failure when the user does not exist', function (): void {
        $throttle = new RecordingLoginThrottle();

        $result = createThrottledGuard($throttle, new FakeUserProvider())
            ->attempt(['identifier' => 99, 'password' => 'secret']);

        expect($result)->toBeFalse()
            ->and($throttle->calls)->toBe(['check:web', 'failure:web']);
    });

    it('clears the throttle on a successful login', function (): void {
        $throttle = new RecordingLoginThrottle();
        $guard = createThrottledGuard($throttle, createPasswordProvider());

        $result = $guard->attempt(['identifier' => 42, 'password' => 'secret']);

        expect($result)->toBeTrue()
            ->and($guard->id())->toBe(42)
            ->and($throttle->calls)->toBe(['check:web', 'clear:web']);
    });

    it('rejects a locked-out attempt before looking the user up, even with the right password', function (): void {
        $throttle = new RecordingLoginThrottle(lockedOut: true);
        $lookups = 0;
        $provider = new FakeUserProvider(
            [42 => new FakeAuthenticatable(id: 42)],
            function () use (&$lookups): bool {
                $lookups++;

                return true;
            },
        );
        $guard = createThrottledGuard($throttle, $provider);

        expect(fn () => $guard->attempt(['identifier' => 42, 'password' => 'secret']))
            ->toThrow(TooManyLoginAttemptsException::class)
            ->and($lookups)->toBe(0)
            ->and($guard->check())->toBeFalse()
            ->and($throttle->calls)->toBe(['check:web']);
    });
});
