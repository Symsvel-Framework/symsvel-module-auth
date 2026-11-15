<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Service;

use SymSvel\Module\Settings\Service\SettingManager;

/** Only trusted server-side Settings determine the email confirmation page. */
final readonly class EmailVerificationUrlResolver
{
    public function __construct(private SettingManager $settings)
    {
    }

    public function forContext(string $context): string
    {
        $key = match ($context) {
            'bo' => 'auth.bo_verify_email_url',
            'app' => 'auth.app_verify_email_url',
            default => throw new \InvalidArgumentException('Unknown email verification context.'),
        };
        $url = trim((string) $this->settings->get($key));
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
}
