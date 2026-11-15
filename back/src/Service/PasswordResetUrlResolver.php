<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Service;

use SymSvel\Module\Settings\Service\SettingManager;

/** Retrieves only server-side configured reset URLs, never request-derived origins. */
final readonly class PasswordResetUrlResolver
{
    public function __construct(private SettingManager $settings)
    {
    }

    public function forContext(string $context): string
    {
        $key = match ($context) {
            'bo' => 'auth.bo_reset_url',
            'app' => 'auth.app_reset_url',
            default => throw new \InvalidArgumentException('Unknown password reset context.'),
        };
        $url = trim((string) $this->settings->get($key));
        $parts = parse_url($url);
        if (!is_array($parts)
            || ($parts['scheme'] ?? null) !== 'https'
            || empty($parts['host'])
            || isset($parts['user']) || isset($parts['pass'])
            || isset($parts['query']) || isset($parts['fragment'])
            || preg_match('/[\r\n]/', $url)) {
            throw new \LogicException('Trusted password reset page URL is not configured.');
        }

        return $url;
    }
}
