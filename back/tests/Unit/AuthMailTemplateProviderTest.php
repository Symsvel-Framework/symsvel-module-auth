<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SymSvel\Module\Auth\Mail\AuthMailTemplateProvider;

final class AuthMailTemplateProviderTest extends TestCase
{
    public function testProvidesLocalizedRecoveryAndVerificationTemplatesForBothContexts(): void
    {
        $templates = iterator_to_array((new AuthMailTemplateProvider())->templates());
        self::assertCount(5, $templates);

        $expected = [
            'auth.bo.password_reset' => ['resetUrl', 'password-reset'],
            'auth.bo.email_verification' => ['verificationUrl', 'email-verification'],
            'auth.app.password_reset' => ['resetUrl', 'password-reset'],
            'auth.app.email_verification' => ['verificationUrl', 'email-verification'],
            'auth.bo.admin_invitation' => ['invitationUrl', 'admin-invitation'],
        ];

        foreach ($templates as $template) {
            self::assertArrayHasKey($template->id, $expected);
            [$variable, $directory] = $expected[$template->id];
            self::assertSame([$variable], $template->variables);
            foreach (['fr', 'en'] as $locale) {
                foreach ($template->locales[$locale] as $twigPath) {
                    self::assertStringStartsWith('@Auth/mail/'.$directory.'/'.$locale.'/', $twigPath);
                    $relative = substr($twigPath, strlen('@Auth/'));
                    self::assertFileExists(__DIR__.'/../../templates/'.$relative);
                }
            }
            unset($expected[$template->id]);
        }
        self::assertSame([], $expected);
    }
}
