<?php

declare(strict_types=1);

use Marko\Authentication\Event\FailedLoginEvent;

it('creates FailedLoginEvent with credentials and guard name', function () {
    $credentials = [
        'email' => 'test@example.com',
        'password' => 'secret123',
    ];

    $event = new FailedLoginEvent(
        credentials: $credentials,
        guard: 'web',
    );

    expect($event->credentials)->toBe(['email' => 'test@example.com'])
        ->and($event->guard)->toBe('web');
});

it('creates FailedLoginEvent without exposing password', function () {
    $credentials = [
        'email' => 'test@example.com',
        'password' => 'super_secret_password_123',
    ];

    $event = new FailedLoginEvent(
        credentials: $credentials,
        guard: 'web',
    );

    expect($event->credentials)->not->toHaveKey('password')
        ->and($event->credentials)->toHaveKey('email');
});

it('strips every secret-looking credential key regardless of case', function () {
    $event = new FailedLoginEvent(
        credentials: [
            'email' => 'test@example.com',
            'password' => 'secret123',
            'password_confirmation' => 'secret123',
            'current_password' => 'old-secret',
            'otp' => '123456',
            'PIN' => '9876',
            'passcode' => '0000',
            'api_token' => 'tok_abc',
            'client_secret' => 'shh',
            'Password' => 'MixedCase',
        ],
        guard: 'web',
    );

    expect($event->credentials)->toBe(['email' => 'test@example.com'])
        ->and($event->getCredentials())->toBe(['email' => 'test@example.com']);
});

it('strips secret-looking keys from nested credential arrays', function () {
    $event = new FailedLoginEvent(
        credentials: [
            'email' => 'test@example.com',
            'mfa' => [
                'otp' => '123456',
                'method' => 'sms',
                'device' => [
                    'remember_token' => 'abc',
                    'name' => 'phone',
                ],
            ],
        ],
        guard: 'web',
    );

    expect($event->credentials)->toBe([
        'email' => 'test@example.com',
        'mfa' => [
            'method' => 'sms',
            'device' => [
                'name' => 'phone',
            ],
        ],
    ]);
});

it('keeps non-secret credential keys untouched', function () {
    $event = new FailedLoginEvent(
        credentials: [
            'email' => 'test@example.com',
            'username' => 'jdoe',
            'remember' => true,
        ],
        guard: 'web',
    );

    expect($event->credentials)->toBe([
        'email' => 'test@example.com',
        'username' => 'jdoe',
        'remember' => true,
    ]);
});
