<?php

declare(strict_types=1);

namespace Marko\Authentication\Tests\Integration;

use Closure;
use Marko\Authentication\AuthManager;
use Marko\Authentication\Contracts\CookieJarInterface;
use Marko\Authentication\Contracts\GuardInterface;
use Marko\Authentication\Contracts\UserProviderInterface;
use Marko\Authentication\Cookie\RequestCookieJar;
use Marko\Authentication\Event\FailedLoginEvent;
use Marko\Authentication\Event\LoginEvent;
use Marko\Authentication\Event\LogoutEvent;
use Marko\Authentication\Guard\SessionGuard;
use Marko\Authentication\Middleware\QueuedCookiesMiddleware;
use Marko\Authentication\Token\RememberTokenManager;
use Marko\Config\ConfigRepository;
use Marko\Config\ConfigRepositoryInterface;
use Marko\Core\Container\Container;
use Marko\Core\Event\Event;
use Marko\Core\Event\EventDispatcher;
use Marko\Core\Event\EventDispatcherInterface;
use Marko\Core\Event\ObserverDefinition;
use Marko\Core\Event\ObserverRegistry;
use Marko\Routing\Http\Cookie;
use Marko\Routing\Http\Request;
use Marko\Routing\Http\Response;
use Marko\Routing\Middleware\MiddlewarePipeline;
use Marko\Session\Contracts\SessionInterface;
use Marko\Session\Middleware\SessionMiddleware;
use Marko\Testing\Fake\FakeAuthenticatable;
use Marko\Testing\Fake\FakeSession;
use Marko\Testing\Fake\FakeUserProvider;
use ReflectionProperty;

class RecordingAuthObserver
{
    /** @var array<int, Event> */
    public array $events = [];

    public function handle(
        Event $event,
    ): void {
        $this->events[] = $event;
    }
}

/**
 * Build a container the way Application does: package config files loaded,
 * the authentication module.php bindings/singletons registered, and core's
 * EventDispatcher bound with observers registered for the auth events.
 *
 * @param array<string, mixed> $rememberCookieOverrides
 */
function bootAuthContainer(
    UserProviderInterface $userProvider,
    RecordingAuthObserver $observer = new RecordingAuthObserver(),
    array $rememberCookieOverrides = [],
): Container {
    $packageRoot = dirname(__DIR__, 2);
    $authentication = require $packageRoot . '/config/authentication.php';
    $authentication['remember']['cookie'] = [...$authentication['remember']['cookie'], ...$rememberCookieOverrides];
    $session = require dirname($packageRoot) . '/session/config/session.php';

    $container = new Container();
    $container->instance(ConfigRepositoryInterface::class, new ConfigRepository([
        'authentication' => $authentication,
        'session' => $session,
    ]));
    $container->instance(SessionInterface::class, new FakeSession());
    $container->instance(UserProviderInterface::class, $userProvider);
    $container->instance(RecordingAuthObserver::class, $observer);

    $registry = new ObserverRegistry();

    foreach ([LoginEvent::class, LogoutEvent::class, FailedLoginEvent::class] as $eventClass) {
        $registry->register(new ObserverDefinition(
            observerClass: RecordingAuthObserver::class,
            eventClass: $eventClass,
        ));
    }

    $container->instance(EventDispatcherInterface::class, new EventDispatcher($container, $registry));

    $module = require $packageRoot . '/module.php';

    foreach ($module['bindings'] as $interface => $implementation) {
        $container->bind($interface, $implementation);
    }

    foreach ($module['singletons'] as $key => $value) {
        if (is_int($key)) {
            $container->singleton($value);
        } else {
            $container->bind($key, $value);
            $container->singleton($key);
        }
    }

    return $container;
}

/**
 * Run a request through SessionMiddleware followed by the authentication
 * module's global middleware, the same order module sequencing produces.
 */
function handleAuthRequest(
    Container $container,
    Request $request,
    Closure $controller,
): Response {
    $module = require dirname(__DIR__, 2) . '/module.php';

    return new MiddlewarePipeline($container)->process(
        [SessionMiddleware::class, ...$module['globalMiddleware']],
        $request,
        fn (Request $request): Response => $controller($container->get(GuardInterface::class), $request),
    );
}

function rememberCookieFrom(
    Response $response,
    string $name = 'remember_session',
): ?Cookie {
    return array_find($response->cookies(), fn (Cookie $cookie): bool => $cookie->name() === $name);
}

describe('booted container', function (): void {
    it(
        'resolves GuardInterface as a SessionGuard with event dispatcher, cookie jar and token manager',
        function (): void {
            $container = bootAuthContainer(new FakeUserProvider());

            $guard = $container->get(GuardInterface::class);
            $read = fn (string $property): mixed => new ReflectionProperty(SessionGuard::class, $property)->getValue(
                $guard,
            );

            expect($guard)->toBeInstanceOf(SessionGuard::class)
                ->and($read('eventDispatcher'))->toBe($container->get(EventDispatcherInterface::class))
                ->and($read('cookieJar'))->toBe($container->get(CookieJarInterface::class))
                ->and($read('tokenManager'))->toBeInstanceOf(RememberTokenManager::class);
        },
    );

    it('shares one RequestCookieJar between the guard and the middleware', function (): void {
        $container = bootAuthContainer(new FakeUserProvider());

        expect($container->get(CookieJarInterface::class))
            ->toBeInstanceOf(RequestCookieJar::class)
            ->toBe($container->get(RequestCookieJar::class));
    });

    it('builds the token manager with the configured remember lifetime', function (): void {
        $container = bootAuthContainer(new FakeUserProvider());

        expect($container->get(RememberTokenManager::class)->lifetimeMinutes())->toBe(43200);
    });

    it('registers QueuedCookiesMiddleware as global middleware after the session drivers', function (): void {
        $module = require dirname(__DIR__, 2) . '/module.php';

        expect($module['globalMiddleware'])->toBe([QueuedCookiesMiddleware::class])
            ->and($module['sequence']['after'])->toContain('marko/session-file')
            ->toContain('marko/session-database');
    });

    it('resolves the same AuthManager-built guard as GuardInterface', function (): void {
        $container = bootAuthContainer(new FakeUserProvider());

        expect($container->get(GuardInterface::class))->toBe($container->get(AuthManager::class)->guard());
    });
});

describe('remember-me through the middleware pipeline', function (): void {
    it('emits a remember cookie with the configured attributes on login with remember', function (): void {
        $user = new FakeAuthenticatable(id: 42);
        $container = bootAuthContainer(
            userProvider: new FakeUserProvider([42 => $user]),
            rememberCookieOverrides: ['domain' => 'example.com', 'same_site' => 'Strict'],
        );

        $response = handleAuthRequest(
            $container,
            new Request(server: ['REQUEST_METHOD' => 'POST', 'REQUEST_URI' => '/login']),
            function (GuardInterface $guard) use ($user): Response {
                $guard->login($user, remember: true);

                return new Response('logged in');
            },
        );

        $setCookie = array_find(
            $response->headerLines(),
            fn (string $line): bool => str_starts_with($line, 'Set-Cookie: remember_session='),
        );
        $expires = strtotime(substr($setCookie, strpos($setCookie, 'Expires=') + 8, 29));

        expect($setCookie)->toStartWith('Set-Cookie: remember_session=42%7C')
            ->toContain('Path=/')
            ->toContain('Domain=example.com')
            ->toContain('Secure')
            ->toContain('HttpOnly')
            ->toContain('SameSite=Strict')
            ->and($expires)->toBeGreaterThan(time() + 43200 * 60 - 60)
            ->and($user->getRememberToken())->not->toBeNull();
    });

    it('authenticates a new request carrying the remember cookie and no session', function (): void {
        $user = new FakeAuthenticatable(id: 42);
        $provider = new FakeUserProvider([42 => $user]);

        $loginResponse = handleAuthRequest(
            bootAuthContainer($provider),
            new Request(),
            function (GuardInterface $guard) use ($user): Response {
                $guard->login($user, remember: true);

                return new Response('logged in');
            },
        );
        $cookieValue = rawurldecode(explode(
            ';',
            substr(rememberCookieFrom($loginResponse)->toSetCookieString(), strlen('remember_session=')),
        )[0]);
        $firstHash = $user->getRememberToken();

        // A fresh container is a fresh request: a new, empty session.
        $seenUser = null;
        $response = handleAuthRequest(
            bootAuthContainer($provider),
            new Request(cookies: ['remember_session' => $cookieValue]),
            function (GuardInterface $guard) use (&$seenUser): Response {
                $seenUser = $guard->user();

                return new Response('home');
            },
        );

        expect($seenUser)->toBe($user)
            ->and($user->getRememberToken())->not->toBe($firstHash)
            ->and(rememberCookieFrom($response))->not->toBeNull();
    });

    it('does not authenticate a request carrying a forged remember cookie', function (): void {
        $user = new FakeAuthenticatable(id: 42);
        $user->setRememberToken(new RememberTokenManager()->hash('real'));

        $seenUser = 'unset';
        handleAuthRequest(
            bootAuthContainer(new FakeUserProvider([42 => $user])),
            new Request(cookies: ['remember_session' => '42|forged']),
            function (GuardInterface $guard) use (&$seenUser): Response {
                $seenUser = $guard->user();

                return new Response('home');
            },
        );

        expect($seenUser)->toBeNull();
    });

    it('emits an expired remember cookie and clears the stored token on logout', function (): void {
        $user = new FakeAuthenticatable(id: 42);
        $provider = new FakeUserProvider([42 => $user]);
        $tokenManager = new RememberTokenManager();
        $user->setRememberToken($tokenManager->hash('plain'));

        $response = handleAuthRequest(
            bootAuthContainer($provider),
            new Request(cookies: ['remember_session' => '42|plain']),
            function (GuardInterface $guard): Response {
                $guard->logout();

                return new Response('bye');
            },
        );

        $cookie = rememberCookieFrom($response)->toSetCookieString();
        $expires = strtotime(substr($cookie, strpos($cookie, 'Expires=') + 8, 29));

        expect($cookie)->toStartWith('remember_session=;')
            ->and($expires)->toBeLessThan(time())
            ->and($user->getRememberToken())->toBeNull()
            ->and($provider->lastRememberTokenUpdate['token'])->toBeNull();
    });
});

describe('auth events through AuthManager', function (): void {
    it('delivers LoginEvent, LogoutEvent and FailedLoginEvent to registered observers', function (): void {
        $user = new FakeAuthenticatable(id: 42);
        $observer = new RecordingAuthObserver();
        $provider = new FakeUserProvider(
            [42 => $user],
            fn ($user, array $credentials): bool => ($credentials['password'] ?? null) === 'secret',
        );

        handleAuthRequest(
            bootAuthContainer($provider, $observer),
            new Request(),
            function (GuardInterface $guard): Response {
                $guard->attempt(['identifier' => 42, 'password' => 'wrong']);
                $guard->attempt(['identifier' => 42, 'password' => 'secret']);
                $guard->logout();

                return new Response('ok');
            },
        );

        expect(array_map(fn (Event $event): string => $event::class, $observer->events))->toBe([
            FailedLoginEvent::class,
            LoginEvent::class,
            LogoutEvent::class,
        ]);
    });
});
