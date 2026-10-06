<?php

declare(strict_types=1);

use Marko\Authentication\AuthManager;
use Marko\Authentication\Config\AuthConfig;
use Marko\Authentication\Middleware\AuthMiddleware;
use Marko\Authentication\Tests\Fixtures\StatelessFakeGuard;
use Marko\Authentication\Token\RememberTokenManager;
use Marko\Core\Container\Container;
use Marko\Routing\Exceptions\HttpException;
use Marko\Routing\Http\Request;
use Marko\Routing\Http\Response;
use Marko\Routing\Middleware\MiddlewarePipeline;
use Marko\Testing\Fake\FakeAuthenticatable;
use Marko\Testing\Fake\FakeConfigRepository;
use Marko\Testing\Fake\FakeCookieJar;
use Marko\Testing\Fake\FakeEventDispatcher;
use Marko\Testing\Fake\FakeSession;
use Marko\Testing\Fake\FakeUserProvider;

// Helper function to create AuthManager with authenticated user
function createAuthManagerWithUser(
    ?FakeAuthenticatable $user = null,
): AuthManager {
    $configRepo = new FakeConfigRepository([
        'authentication.remember.cookie.prefix' => 'remember_',
        'authentication.default.guard' => 'web',
        'authentication.guards' => [
            'web' => ['driver' => 'session', 'provider' => 'users'],
            'api' => ['driver' => 'token', 'provider' => 'users'],
        ],
    ]);

    $authConfig = new AuthConfig($configRepo);
    $session = new FakeSession();
    $session->start();
    $provider = $user !== null
        ? new FakeUserProvider([$user->getAuthIdentifier() => $user])
        : new FakeUserProvider();

    $manager = new AuthManager(
        config: $authConfig,
        session: $session,
        provider: $provider,
        eventDispatcher: new FakeEventDispatcher(),
        cookieJar: new FakeCookieJar(),
        rememberTokenManager: new RememberTokenManager(),
        guardDriverRegistry: StatelessFakeGuard::tokenDriverRegistry(),
    );

    // If user provided, authenticate them
    if ($user !== null) {
        $manager->attempt(['email' => 'test@example.com', 'password' => 'password']);
    }

    return $manager;
}

test('it allows authenticated users through', function (): void {
    $user = new FakeAuthenticatable(id: 1);
    $authManager = createAuthManagerWithUser($user);

    $middleware = new AuthMiddleware($authManager);

    $request = new Request();
    $expectedResponse = new Response(body: 'success', statusCode: 200);

    $response = $middleware->handle(
        $request,
        fn (Request $r) => $expectedResponse,
    );

    expect($response)->toBe($expectedResponse)
        ->and($response->statusCode())->toBe(200);
});

test('it blocks unauthenticated users', function (): void {
    $authManager = createAuthManagerWithUser(); // No user

    $middleware = new AuthMiddleware($authManager);

    $request = new Request();
    $nextCalled = false;

    $response = $middleware->handle(
        $request,
        function () use (&$nextCalled): Response {
            $nextCalled = true;

            return new Response(body: 'success', statusCode: 200);
        },
    );

    expect($nextCalled)->toBeFalse()
        ->and($response->statusCode())->not->toBe(200);
});

test('it throws 401 instead of redirecting for a stateless guard', function (): void {
    $middleware = new AuthMiddleware(
        auth: createAuthManagerWithUser(),
        guard: 'api',
        redirectTo: '/login',
    );

    expect(fn () => $middleware->handle(
        new Request(),
        fn (Request $r) => new Response(body: 'success', statusCode: 200),
    ))->toThrow(HttpException::class, 'Unauthorized.');
});

test("it sends the stateless guard's challenge in the WWW-Authenticate header", function (): void {
    $middleware = new AuthMiddleware(
        auth: createAuthManagerWithUser(),
        guard: 'api',
    );

    try {
        $middleware->handle(
            new Request(),
            fn (Request $r) => new Response(body: 'success', statusCode: 200),
        );
        $this->fail('Expected HttpException');
    } catch (HttpException $exception) {
        expect($exception->getStatusCode())->toBe(401)
            ->and($exception->getHeaders())->toBe(['WWW-Authenticate' => 'Bearer']);
    }
});

test('it throws 401 instead of redirecting when the request wants JSON', function (): void {
    $middleware = new AuthMiddleware(
        auth: createAuthManagerWithUser(),
        guard: 'web',
        redirectTo: '/login',
    );

    try {
        $middleware->handle(
            new Request(server: ['HTTP_ACCEPT' => 'application/json']),
            fn (Request $r) => new Response(body: 'success', statusCode: 200),
        );
        $this->fail('Expected HttpException');
    } catch (HttpException $exception) {
        expect($exception->getStatusCode())->toBe(401)
            ->and($exception->getHeaders())->toBeEmpty();
    }
});

test('it still redirects a guest on a stateful guard for an HTML request', function (): void {
    $middleware = new AuthMiddleware(
        auth: createAuthManagerWithUser(),
        guard: 'web',
        redirectTo: '/login',
    );

    $response = $middleware->handle(
        new Request(server: ['HTTP_ACCEPT' => 'text/html,application/xhtml+xml']),
        fn (Request $r) => new Response(body: 'success', statusCode: 200),
    );

    expect($response->statusCode())->toBe(302)
        ->and($response->headers()['Location'])->toBe('/login');
});

test('it lets an authenticated request through a stateless guard', function (): void {
    $authManager = createAuthManagerWithUser();
    $guard = $authManager->guard('api');
    assert($guard instanceof StatelessFakeGuard);
    $guard->setUser(new FakeAuthenticatable(id: 7));

    $response = new AuthMiddleware(auth: $authManager, guard: 'api')->handle(
        new Request(),
        fn (Request $r) => new Response(body: 'success', statusCode: 200),
    );

    expect($response->statusCode())->toBe(200);
});

test('it throws a 401 HttpException when unauthenticated and redirectTo is null', function (): void {
    $middleware = new AuthMiddleware(
        auth: createAuthManagerWithUser(),
        guard: 'web',
        redirectTo: null,
    );

    try {
        $middleware->handle(
            new Request(),
            fn (Request $r) => new Response(body: 'success', statusCode: 200),
        );
        $this->fail('Expected HttpException');
    } catch (HttpException $exception) {
        expect($exception->getStatusCode())->toBe(401)
            ->and($exception->getHeaders())->toBeEmpty();
    }
});

test('it renders the 401 as JSON or HTML through the pipeline for session and token guards', function (
    string $guard,
    string $accept,
    string $contentType,
): void {
    $authManager = createAuthManagerWithUser();
    $container = new Container();
    $container->instance(
        AuthMiddleware::class,
        new AuthMiddleware(auth: $authManager, guard: $guard, redirectTo: null),
    );

    $response = new MiddlewarePipeline($container)->process(
        [AuthMiddleware::class],
        new Request(server: ['HTTP_ACCEPT' => $accept]),
        fn (Request $r) => new Response(body: 'success', statusCode: 200),
    );

    expect($response->statusCode())->toBe(401)
        ->and($response->headers()['Content-Type'])->toContain($contentType)
        ->and($response->body())->toContain('Unauthorized')
        ->not->toContain('success');
})->with([
    'session guard, JSON' => ['web', 'application/json', 'application/json'],
    'session guard, HTML' => ['web', 'text/html', 'text/html'],
    'token guard, JSON' => ['api', 'application/vnd.api+json', 'application/json'],
    'token guard, HTML' => ['api', 'text/html', 'text/html'],
]);

test('it redirects for web guard when unauthenticated', function (): void {
    $authManager = createAuthManagerWithUser();

    $middleware = new AuthMiddleware(
        auth: $authManager,
        guard: 'web',
        redirectTo: '/login',
    );

    $request = new Request();

    $response = $middleware->handle(
        $request,
        fn (Request $r) => new Response(body: 'success', statusCode: 200),
    );

    expect($response->statusCode())->toBe(302)
        ->and($response->headers())->toHaveKey('Location')
        ->and($response->headers()['Location'])->toBe('/login');
});

test('it supports specifying guard via parameter', function (): void {
    $user = new FakeAuthenticatable(id: 1);
    $configRepo = new FakeConfigRepository([
        'authentication.remember.cookie.prefix' => 'remember_',
        'authentication.default.guard' => 'web',
        'authentication.guards' => [
            'web' => ['driver' => 'session', 'provider' => 'users'],
            'api' => ['driver' => 'token', 'provider' => 'users'],
        ],
    ]);

    $authConfig = new AuthConfig($configRepo);
    $session = new FakeSession();
    $session->start();
    $provider = new FakeUserProvider([1 => $user]);

    $authManager = new AuthManager(
        config: $authConfig,
        session: $session,
        provider: $provider,
        eventDispatcher: new FakeEventDispatcher(),
        cookieJar: new FakeCookieJar(),
        rememberTokenManager: new RememberTokenManager(),
        guardDriverRegistry: StatelessFakeGuard::tokenDriverRegistry(),
    );

    // Authenticate on web guard
    $authManager->attempt(['email' => 'test@example.com', 'password' => 'password']);

    // Middleware using 'api' guard should fail (user not authenticated on api guard)
    $middleware = new AuthMiddleware(
        auth: $authManager,
        guard: 'api',
    );

    // The user is authenticated on the web guard only, so the API guard rejects the request
    expect(fn () => $middleware->handle(
        new Request(),
        fn (Request $r) => new Response(body: 'success', statusCode: 200),
    ))->toThrow(HttpException::class);
});

test('it uses default guard when not specified', function (): void {
    $user = new FakeAuthenticatable(id: 1);
    $authManager = createAuthManagerWithUser($user);

    // Middleware without guard parameter uses default (web)
    $middleware = new AuthMiddleware(
        auth: $authManager,
    );

    $request = new Request();
    $expectedResponse = new Response(body: 'success', statusCode: 200);

    $response = $middleware->handle(
        $request,
        fn (Request $r) => $expectedResponse,
    );

    // User is authenticated on default guard, so request passes through
    expect($response)->toBe($expectedResponse)
        ->and($response->statusCode())->toBe(200);
});
