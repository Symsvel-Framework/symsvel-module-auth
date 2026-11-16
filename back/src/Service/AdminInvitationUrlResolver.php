<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Service;

use SymSvel\Module\Settings\Service\SettingManager;

final readonly class AdminInvitationUrlResolver
{
    public function __construct(private SettingManager $settings) {}

    public function resolve(): string
    {
        $url = trim((string) $this->settings->get('auth.bo_invitation_url'));
        $parts = parse_url($url);
        if (!is_array($parts) || strtolower((string) ($parts['scheme'] ?? '')) !== 'https'
            || empty($parts['host']) || isset($parts['user']) || isset($parts['pass'])
            || isset($parts['query']) || isset($parts['fragment']) || preg_match('/[\r\n]/', $url)) {
            throw new \LogicException('Trusted BO invitation page URL is not configured.');
        }

        return $url;
    }
}
