<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Service;

use Symfony\Component\DependencyInjection\Attribute\Autowire;
use SymSvel\Module\Settings\Service\SettingManager;

/** Resolve mail links from trusted project metadata, never the request Host. */
final readonly class EmailVerificationUrlResolver
{
    public function __construct(
        private SettingManager $settings,
        #[Autowire('%kernel.project_dir%')] private string $backendDirectory,
    ) {
    }

    public function forContext(string $context): string
    {
        if ($context === 'app') {
            return $this->appVerificationUrl();
        }
        if ($context !== 'bo') {
            throw new \InvalidArgumentException('Unknown email verification context.');
        }

        $url = trim((string) $this->settings->get('auth.bo_verify_email_url'));
        $parts = parse_url($url);
        if (!is_array($parts)
            || strtolower((string) ($parts['scheme'] ?? '')) !== 'https'
            || empty($parts['host'])
            || isset($parts['user']) || isset($parts['pass'])
            || isset($parts['query']) || isset($parts['fragment'])
            || preg_match('/[\r\n]/', $url)) {
            throw new \LogicException('Trusted email verification page URL is not configured.');
        }

        return $url;
    }

    private function appVerificationUrl(): string
    {
        // Setup metadata is stored at workspace/.symsvel/project.json.
        // backend/.symsvel/project.json holds only the dev/stable channel.
        $path = dirname($this->backendDirectory).'/.symsvel/project.json';
        if (!is_file($path) || !is_readable($path) || is_link($path)) {
            throw new \LogicException('Trusted project domain is not configured.');
        }
        $json = file_get_contents($path);
        if ($json === false) {
            throw new \LogicException('Trusted project domain is not configured.');
        }
        try {
            $metadata = json_decode($json, true, 16, JSON_THROW_ON_ERROR);
        } catch (\JsonException $exception) {
            throw new \LogicException('Trusted project domain is not configured.', 0, $exception);
        }

        $domain = is_array($metadata) ? ($metadata['local_domain'] ?? null) : null;
        if (($metadata['schema'] ?? null) !== 1 || !is_string($domain)
            || !preg_match('/^(?=.{1,253}$)[a-z0-9]+(?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9]+(?:[a-z0-9-]*[a-z0-9])?)*$/D', $domain)) {
            throw new \LogicException('Trusted project domain is not configured.');
        }

        return 'https://app.'.$domain.'/verify-email';
    }
}
