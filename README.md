# marko/authentication

Session and token-based authentication---guards protect routes, remember-me keeps users signed in, events track activity, middleware controls access.

## Installation

```bash
composer require marko/authentication
```

## Quick Example

```php
use Marko\Authentication\AuthManager;
use Marko\Routing\Http\Response;

class LoginController
{
    public function __construct(
        private AuthManager $authManager,
    ) {}

    public function login(array $credentials): Response
    {
        if ($this->authManager->attempt($credentials)) {
            return Response::redirect('/dashboard');
        }

        return new Response('Invalid credentials', 401);
    }
}
```

## Documentation

Full usage, configuration, remember-me setup, events, and API reference: [marko/authentication](https://marko.build/docs/packages/authentication/)
