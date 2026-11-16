<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SymSvel\Module\Auth\Service\AuthPageUrls;
use SymSvel\Module\Auth\Service\AuthSettingDefinitionProvider;
use SymSvel\Module\Auth\Service\PasswordResetUrlResolver;
use SymSvel\Module\Auth\Service\EmailVerificationUrlResolver;
use SymSvel\Module\Auth\Service\AdminInvitationUrlResolver;
use SymSvel\Module\Auth\Service\AppInvitationUrlResolver;
use SymSvel\Module\Settings\Service\SettingRegistry;
use SymSvel\Module\Settings\Service\SettingKeyQualifier;

final class AuthSettingDefinitionProviderTest extends TestCase
{
    public function testAuthExposesNoMutableUrlSettings(): void
    {
        $registry = new SettingRegistry([]);
        $registry->registerOwned(new AuthSettingDefinitionProvider(), 'auth', new SettingKeyQualifier());
        self::assertSame([], $registry->all());
    }

    public function testAllCallbackUrlsUseSetupPublishedDomainAndKnownRoutes(): void
    {
        $pages = new AuthPageUrls('prod', 'xt.localhost');
        self::assertSame('https://bo.xt.localhost/reset-password', (new PasswordResetUrlResolver($pages))->forContext('bo'));
        self::assertSame('https://app.xt.localhost/reset-password', (new PasswordResetUrlResolver($pages))->forContext('app'));
        self::assertSame('https://bo.xt.localhost/verify-email', (new EmailVerificationUrlResolver($pages))->forContext('bo'));
        self::assertSame('https://app.xt.localhost/verify-email', (new EmailVerificationUrlResolver($pages))->forContext('app'));
        self::assertSame('https://bo.xt.localhost/auth/activate', (new AdminInvitationUrlResolver($pages))->resolve());
        self::assertSame('https://app.xt.localhost/activate', (new AppInvitationUrlResolver($pages))->resolve());
    }

    public function testMissingOrUntrustedSetupDomainFailsClosed(): void
    {
        foreach ([null, 'evil.test/path', 'https://bad.test', 'UPPER.test', 'bad..test'] as $domain) {
            $pages = new AuthPageUrls('prod', $domain ?? '');
            try {
                $pages->forPage('bo', 'reset');
                self::fail('Missing or malformed domain must be rejected.');
            } catch (\LogicException) {
            }
        }
    }

    public function testLocalDevelopmentUsesHttpForReservedDomainsWithoutRequestHost(): void
    {
        $pages = new AuthPageUrls('dev', 'xt.localhost');
        self::assertSame('http://bo.xt.localhost/auth/activate', $pages->forPage('bo', 'invitation'));
        self::assertSame('http://app.xt.localhost/verify-email', $pages->forPage('app', 'verify'));
        $public = new AuthPageUrls('dev', 'example.org');
        self::assertSame('https://bo.example.org/reset-password', $public->forPage('bo', 'reset'));
    }

    public function testProductionCanUseExplicitDeploymentOriginsButNeverHttp(): void
    {
        $pages = new AuthPageUrls('prod', 'project.example.test',
            'https://admin.example.org', 'https://portal.example.org');
        self::assertSame('https://admin.example.org/auth/activate', $pages->forPage('bo', 'invitation'));
        self::assertSame('https://portal.example.org/verify-email', $pages->forPage('app', 'verify'));

        $this->expectException(\LogicException::class);
        (new AuthPageUrls('prod', 'project.example.test', 'http://bo.project.example.test'))
            ->forPage('bo', 'reset');
    }

    public function testLocalHttpIsExplicitOptInOnlyForSetupDomain(): void
    {
        $pages = new AuthPageUrls('dev', 'xt.localhost', 'http://bo.xt.localhost:8000');
        self::assertSame('http://bo.xt.localhost:8000/auth/activate', $pages->forPage('bo', 'invitation'));

        $this->expectException(\LogicException::class);
        (new AuthPageUrls('dev', 'xt.localhost', 'http://evil.test'))
            ->forPage('bo', 'reset');
    }

    public function testRejectsHostInjectionAndUnknownPages(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        (new AuthPageUrls('dev', 'xt.localhost'))->forPage('bo', 'unknown');
    }

    public function testRejectsOriginWithPathOrCredentials(): void
    {
        foreach (['https://bo.xt.localhost/evil', 'https://user:pass@bo.xt.localhost',
            'https://bo.xt.localhost?to=evil', 'javascript:alert(1)'] as $origin) {
            try {
                (new AuthPageUrls('prod', 'xt.localhost', $origin))->forPage('bo', 'reset');
                self::fail('Unsafe origin accepted: '.$origin);
            } catch (\LogicException) {
            }
        }
    }
}
