<?php

declare(strict_types=1);

namespace Marko\Authentication\Config;

use Marko\Config\ConfigRepositoryInterface;
use Marko\Config\Exceptions\ConfigNotFoundException;

readonly class AuthConfig
{
    public function __construct(
        private ConfigRepositoryInterface $config,
    ) {}

    public function defaultGuard(): string
    {
        return $this->config->getString('authentication.default.guard');
    }

    public function defaultProvider(): string
    {
        return $this->config->getString('authentication.default.provider');
    }

    /**
     * The default provider name, or null when authentication.default.provider is not set.
     */
    public function defaultProviderOrNull(): ?string
    {
        return $this->config->has('authentication.default.provider')
            ? $this->config->getString('authentication.default.provider')
            : null;
    }

    /**
     * @return array<string, array<string, mixed>>
     */
    public function guards(): array
    {
        return $this->config->getArray('authentication.guards');
    }

    /**
     * @return array<string, array<string, mixed>>
     */
    public function providers(): array
    {
        return $this->config->getArray('authentication.providers');
    }

    /**
     * The configured providers, or null when authentication.providers is not set.
     *
     * @return array<string, mixed>|null
     */
    public function providersOrNull(): ?array
    {
        return $this->config->has('authentication.providers')
            ? $this->config->getArray('authentication.providers')
            : null;
    }

    /**
     * @return array<string, mixed>
     */
    public function passwordConfig(): array
    {
        return $this->config->getArray('authentication.password');
    }

    /**
     * @return array<string, mixed>
     */
    public function rememberConfig(): array
    {
        return $this->config->getArray('authentication.remember');
    }

    /**
     * @throws ConfigNotFoundException
     */
    public function bcryptCost(): int
    {
        return $this->config->getInt('authentication.password.bcrypt.cost');
    }

    /**
     * Remember-me lifetime in minutes.
     *
     * @throws ConfigNotFoundException
     */
    public function rememberLifetime(): int
    {
        return $this->config->getInt('authentication.remember.lifetime');
    }

    /**
     * @throws ConfigNotFoundException
     */
    public function rememberCookiePrefix(): string
    {
        return $this->config->getString('authentication.remember.cookie.prefix');
    }

    /**
     * @throws ConfigNotFoundException
     */
    public function rememberCookiePath(): string
    {
        return $this->config->getString('authentication.remember.cookie.path');
    }

    /**
     * @throws ConfigNotFoundException
     */
    public function rememberCookieDomain(): ?string
    {
        $domain = $this->config->getString('authentication.remember.cookie.domain');

        return $domain !== '' ? $domain : null;
    }

    /**
     * Whether the remember cookie is marked Secure. A null config value follows
     * the session cookie's secure flag so both cookies stay consistent.
     *
     * @throws ConfigNotFoundException
     */
    public function rememberCookieSecure(): bool
    {
        $secure = $this->config->get('authentication.remember.cookie.secure');

        if ($secure === null) {
            return $this->config->getBool('session.cookie.secure');
        }

        return (bool) $secure;
    }

    /**
     * @throws ConfigNotFoundException
     */
    public function rememberCookieHttpOnly(): bool
    {
        return $this->config->getBool('authentication.remember.cookie.http_only');
    }

    /**
     * @throws ConfigNotFoundException
     */
    public function rememberCookieSameSite(): string
    {
        return $this->config->getString('authentication.remember.cookie.same_site');
    }
}
