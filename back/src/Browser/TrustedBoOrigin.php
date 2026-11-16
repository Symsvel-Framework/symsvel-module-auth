<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Browser;

use Symfony\Component\DependencyInjection\Attribute\Autowire;
use Symfony\Component\HttpFoundation\Request;

/**
 * Origin validation is anchored in Setup metadata or an explicit HTTPS override.
 * Local HTTP is available only in dev for reserved local domains and an HTTP backend.
 */
final readonly class TrustedBoOrigin
{
    public function __construct(
        #[Autowire('%kernel.project_dir%')] private string $backendDirectory,
        private ?string $explicitOrigin = null,
        #[Autowire('%kernel.environment%')] private string $environment = 'prod',
    ) {
    }

    public function accepts(Request $request): bool
    {
        $given = $request->headers->get('Origin');
        if (!is_string($given) || $given === '' || $given === 'null') {
            return false;
        }

        $override = $this->explicitOrigin ?? ($_SERVER['SYMSVEL_BO_ORIGIN'] ?? $_ENV['SYMSVEL_BO_ORIGIN'] ?? null);
        if (is_string($override) && $override !== '') {
            if (!$this->isBareOrigin($override, 'https')) {
                return false;
            }

            return hash_equals($override, $given);
        }

        $domain = $this->localDomain();
        if ($domain === null || !$this->isBareOrigin($given)) {
            return false;
        }
        $parts = parse_url($given);
        if (!is_array($parts) || ($parts['host'] ?? null) !== 'bo.'.$domain) {
            return false;
        }

        $scheme = $parts['scheme'] ?? '';
        if ($scheme === 'https') {
            // Non-default HTTPS development ports are not accepted in production
            // unless supplied explicitly through SYMSVEL_BO_ORIGIN.
            return !isset($parts['port']) || $this->environment === 'dev';
        }

        return $scheme === 'http'
            && $this->environment === 'dev'
            && !$request->isSecure()
            && preg_match('/\.(?:localhost|local|test)$/D', $domain) === 1;
    }

    /** Insecure cookies are restricted to the explicitly validated local HTTP origin. */
    public function usesLocalHttpCookie(Request $request): bool
    {
        return $this->accepts($request)
            && str_starts_with((string) $request->headers->get('Origin'), 'http://');
    }

    /** Strict origin format: no userinfo, path, query, fragment or control characters. */
    private function isBareOrigin(string $origin, ?string $requiredScheme = null): bool
    {
        if (preg_match('/[\x00-\x20\x7f]/', $origin)) {
            return false;
        }
        $parts = parse_url($origin);
        if (!is_array($parts) || !isset($parts['scheme'], $parts['host'])) {
            return false;
        }
        if (!in_array($parts['scheme'], ['http', 'https'], true)
            || ($requiredScheme !== null && $parts['scheme'] !== $requiredScheme)
            || preg_match('/^[a-z0-9.-]+$/D', $parts['host']) !== 1) {
            return false;
        }
        foreach (['user', 'pass', 'path', 'query', 'fragment'] as $forbidden) {
            if (array_key_exists($forbidden, $parts)) {
                return false;
            }
        }

        return !isset($parts['port']) || ($parts['port'] >= 1 && $parts['port'] <= 65535);
    }

    private function localDomain(): ?string
    {
        $path = dirname($this->backendDirectory).'/.symsvel/project.json';
        if (!is_file($path) || !is_readable($path) || is_link($path)) {
            return null;
        }
        try {
            $data = json_decode((string) file_get_contents($path), true, 16, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return null;
        }
        $domain = is_array($data) ? ($data['local_domain'] ?? null) : null;
        if (($data['schema'] ?? null) !== 1 || !is_string($domain)
            || !preg_match('/^(?=.{1,253}$)[a-z0-9]+(?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9]+(?:[a-z0-9-]*[a-z0-9])?)*$/D', $domain)) {
            return null;
        }

        return $domain;
    }
}
