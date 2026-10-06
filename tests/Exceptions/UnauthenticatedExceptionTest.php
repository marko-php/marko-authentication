<?php

declare(strict_types=1);

use Marko\Authentication\Exceptions\UnauthenticatedException;
use Marko\Authentication\Tests\Fixtures\StatelessFakeGuard;
use Marko\Routing\Exceptions\HttpException;
use Marko\Testing\Fake\FakeGuard;

describe('UnauthenticatedException', function (): void {
    it('builds a 401 HttpException for a guest', function (): void {
        $exception = UnauthenticatedException::forGuard(new FakeGuard(name: 'web'));

        expect($exception)->toBeInstanceOf(HttpException::class)
            ->and($exception->getStatusCode())->toBe(401);
    });

    it('uses Unauthorized. as the client-facing message', function (): void {
        $exception = UnauthenticatedException::forGuard(new FakeGuard(name: 'web'));

        expect($exception->getMessage())->toBe('Unauthorized.')
            ->and($exception->getResponseData())->toBe(['message' => 'Unauthorized.']);
    });

    it("adds the stateless guard's challenge as the WWW-Authenticate header", function (): void {
        $exception = UnauthenticatedException::forGuard(new StatelessFakeGuard(name: 'api'));

        expect($exception->getHeaders())->toBe(['WWW-Authenticate' => 'Bearer']);
    });

    it('sends no WWW-Authenticate header for a stateful guard', function (): void {
        $exception = UnauthenticatedException::forGuard(new FakeGuard(name: 'web'));

        expect($exception->getHeaders())->toBe([]);
    });

    it('names the guard in the log-only context', function (): void {
        $exception = UnauthenticatedException::forGuard(new FakeGuard(name: 'web'));

        expect($exception->getContext())->toContain("'web'")
            ->and($exception->getMessage())->not->toContain('web');
    });
});
