<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Service;

use Symfony\Component\DependencyInjection\Attribute\Autowire;

/**
 * URLs derived from the Setup-published runtime domain, never from HTTP Host,
 * BO Settings, query parameters, or private Setup metadata.
 *
 * Explicit origins are deployment configuration, not editable application data.
 */
final readonly class AuthPageUrls
{
    public function __construct(
        #[Autowire('%kernel.environment%')] private string $environment = 'prod',
        private ?string $configuredDomain = null,
        private ?string $configuredBoOrigin = null,
        private ?string $configuredAppOrigin = null,
    ) {
    }

    public function forPage(string $context, string $page): string
    {
        $path = match ($context.':'.$page) {
            'bo:reset' => '/reset-password',
            'bo:verify' => '/verify-email',
            'bo:invitation' => '/auth/activate',
            'app:reset' => '/reset-password',
            'app:verify' => '/verify-email',
            'app:invitation' => '/activate',
            default => throw new \InvalidArgumentException('Unknown authentication page.'),
        };

        return $this->origin($context).$path;
    }

    private function origin(string $context): string
    {
        $explicit = match ($context) {
            'bo' => $this->configuredBoOrigin ?? self::environmentVariable('SYMSVEL_BO_ORIGIN'),
            'app' => $this->configuredAppOrigin ?? self::environmentVariable('SYMSVEL_APP_ORIGIN'),
            default => throw new \InvalidArgumentException('Unknown authentication context.'),
        };

        if ($explicit === null || $explicit === '') {
            $domain = $this->domain();
            $expectedHost = $context.'.'.$domain;
            // A development virtual host is usually served over local HTTP.
            // Production and non-reserved domains always default to HTTPS.
            $local = $this->environment === 'dev'
                && preg_match('/\.(?:localhost|local|test)$/D', $domain) === 1;
            return ($local ? 'http://' : 'https://').$expectedHost;
        }

        $parts = parse_url($explicit);
        if (!is_array($parts) || !isset($parts['scheme'], $parts['host'])
            || !in_array($parts['scheme'], ['https', 'http'], true)
            || preg_match('/^[a-z0-9.-]+$/D', $parts['host']) !== 1
            || isset($parts['user'], $parts['pass'])
            || preg_match('/[\x00-\x20\x7f]/', $explicit)) {
            throw new \LogicException('Invalid trusted authentication origin.');
        }
        foreach (['user', 'pass', 'path', 'query', 'fragment'] as $forbidden) {
            if (array_key_exists($forbidden, $parts)) {
                throw new \LogicException('Invalid trusted authentication origin.');
            }
        }
        if (isset($parts['port']) && ($parts['port'] < 1 || $parts['port'] > 65535)) {
            throw new \LogicException('Invalid trusted authentication origin.');
        }
        if ($parts['scheme'] === 'http'
            && ($this->environment !== 'dev'
                || $parts['host'] !== $context.'.'.$this->domain())) {
            throw new \LogicException('Insecure authentication origin is forbidden.');
        }
        if ($parts['scheme'].'://'.$parts['host'].(isset($parts['port']) ? ':'.$parts['port'] : '') !== $explicit) {
            throw new \LogicException('Invalid trusted authentication origin.');
        }

        return $explicit;
    }

    private function domain(): string
    {
        $domain = $this->configuredDomain ?? self::environmentVariable('SYMSVEL_BO_DOMAIN');
        if (!is_string($domain) || strlen($domain) > 253
            || !preg_match('/^(?=.{1,253}$)[a-z0-9]+(?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9]+(?:[a-z0-9-]*[a-z0-9])?)*$/D', $domain)) {
            throw new \LogicException('Trusted project domain is not configured.');
        }

        return $domain;
    }

    private static function environmentVariable(string $name): ?string
    {
        $value = $_SERVER[$name] ?? $_ENV[$name] ?? getenv($name);
        return is_string($value) && $value !== '' ? $value : null;
    }
}
