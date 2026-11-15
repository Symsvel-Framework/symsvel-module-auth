<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SymSvel\Module\Auth\Mail\AuthMailTemplateProvider;

final class AuthMailTemplateProviderTest extends TestCase
{
    public function testProvidesIsolatedBoAndAppTemplatesWithLocalizedFiles(): void
    {
        $templates = iterator_to_array((new AuthMailTemplateProvider())->templates());
        self::assertCount(2, $templates);
        self::assertSame('auth.bo.password_reset', $templates[0]->id);
        self::assertSame('auth.app.password_reset', $templates[1]->id);
        foreach ($templates as $template) {
            self::assertSame(['resetUrl'], $template->variables);
            foreach (['fr', 'en'] as $locale) {
                foreach ($template->locales[$locale] as $twigPath) {
                    self::assertStringStartsWith('@Auth/mail/password-reset/'.$locale.'/', $twigPath);
                    $relative = substr($twigPath, strlen('@Auth/'));
                    self::assertFileExists(__DIR__.'/../../templates/'.$relative);
                }
            }
        }
    }
}
