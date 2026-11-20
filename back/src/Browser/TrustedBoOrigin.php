<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Browser;

use Symfony\Component\DependencyInjection\Attribute\Autowire;
use Symfony\Component\HttpFoundation\Request;

/**
 * Check the exact BO Origin against public runtime configuration.
 *
 * The Setup workspace metadata is deliberately private (0700/0600) and
 * must never be accessed by a PHP-FPM request. Tooling publishes only the
 * validated domain into backend/.env.local as SYMSVEL_BO_DOMAIN.
 */
final readonly class TrustedBoOrigin
{
    public function __construct(
        #[Autowire('%kernel.environment%')] private string $environment = 'prod',
        private ?string $configuredDomain = null,
        private ?string $explicitOrigin = null,
    ) {
    }

    public function accepts(Request $request): bool
    {
        $given = $request->headers->get('Origin');
        if (!is_string($given) || $given === '' || $given === 'null') {
            return false;
        }

        $override = $this->explicitOrigin
            ?? ($_SERVER['SYMSVEL_BO_ORIGIN'] ?? $_ENV['SYMSVEL_BO_ORIGIN'] ?? getenv('SYMSVEL_BO_ORIGIN') ?: null);
        if (is_string($override) && $override !== '') {
            return $this->isBareOrigin($override, 'https') && hash_equals($override, $given);
        }

        $domain = $this->runtimeDomain();
        if ($domain === null || !$this->isBareOrigin($given)) {
            return false;
        }
        $parts = parse_url($given);
        if (!is_array($parts) || ($parts['host'] ?? null) !== 'bo.'.$domain) {
            return false;
        }

        $scheme = $parts['scheme'] ?? '';
        if ($scheme === 'https') {
            // A production nonstandard port must be explicitly configured.
            return !isset($parts['port']) || $this->environment === 'dev';
        }

        if ($scheme !== 'http' || $this->environment !== 'dev' || $request->isSecure()) {
            return false;
        }

        // Setup accepts custom local virtual-host domains, including names
        // ending in .fr. HTTP is permitted only for a reserved local name OR
        // a request actually received over loopback; never for a remote client.
        $reservedName = preg_match('/\.(?:localhost|local|test)$/D', $domain) === 1;
        $loopbackClient = in_array($request->server->get('REMOTE_ADDR'), ['127.0.0.1', '::1'], true);
        return $reservedName || $loopbackClient;
    }

    /** Never mark cookies Secure=false outside a validated local HTTP request. */
    public function usesLocalHttpCookie(Request $request): bool
    {
        return $this->accepts($request)
            && str_starts_with((string) $request->headers->get('Origin'), 'http://');
    }

    private function runtimeDomain(): ?string
    {
        $candidate = $this->configuredDomain
            ?? ($_SERVER['SYMSVEL_BO_DOMAIN'] ?? $_ENV['SYMSVEL_BO_DOMAIN'] ?? getenv('SYMSVEL_BO_DOMAIN') ?: null);
        if (!is_string($candidate) ||
            !preg_match('/^(?=.{1,253}$)[a-z0-9]+(?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9]+(?:[a-z0-9-]*[a-z0-9])?)*$/D', $candidate)) {
            return null;
        }
        return $candidate;
    }

    /** Reject noncanonical, opaque, malformed and navigational origins. */
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
}
