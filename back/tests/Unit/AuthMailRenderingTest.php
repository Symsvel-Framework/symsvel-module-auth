<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SymSvel\Module\Auth\Mail\AuthMailTemplateProvider;
use SymSvel\Module\Mails\Mail\MailTemplateRegistry;
use SymSvel\Module\Mails\Mail\RegisteredMailRenderer;
use Twig\Environment;
use Twig\Loader\FilesystemLoader;

final class AuthMailRenderingTest extends TestCase
{
    public function testRendersBothContextsInFrenchAndEnglish(): void
    {
        $loader = new FilesystemLoader();
        $loader->addPath(__DIR__.'/../../templates', 'Auth');
        $renderer = new RegisteredMailRenderer(
            new MailTemplateRegistry([new AuthMailTemplateProvider()]),
            new Environment($loader, ['autoescape' => 'name']),
        );
        foreach (['bo', 'app'] as $context) {
            foreach (['fr', 'en'] as $locale) {
                $mail = $renderer->render('auth.'.$context.'.password_reset', $locale, [
                    'resetUrl' => 'https://example.test/reset?token=abc&context='.$context,
                ]);
                self::assertNotSame('', $mail->subject);
                self::assertStringContainsString('https://example.test/reset?token=abc&amp;context='.$context, $mail->html);
                self::assertStringContainsString('https://example.test/reset?token=abc&context='.$context, $mail->text);
            }
        }
    }
}
