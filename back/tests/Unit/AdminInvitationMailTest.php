<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SymSvel\Module\Auth\Mail\AuthMailTemplateProvider;
use SymSvel\Module\Mails\Mail\MailTemplateRegistry;
use SymSvel\Module\Mails\Mail\RegisteredMailRenderer;
use Twig\Environment;
use Twig\Loader\FilesystemLoader;

final class AdminInvitationMailTest extends TestCase
{
    public function testLocalizedInvitationRendersLink(): void
    {
        $loader = new FilesystemLoader();
        $loader->addPath(__DIR__.'/../../templates', 'Auth');
        $renderer = new RegisteredMailRenderer(new MailTemplateRegistry([new AuthMailTemplateProvider()]), new Environment($loader, ['autoescape' => 'name']));
        foreach (['fr', 'en'] as $locale) {
            $mail = $renderer->render('auth.bo.admin_invitation', $locale, ['invitationUrl' => 'https://bo.example.test/activate?token=opaque']);
            self::assertNotSame('', $mail->subject);
            self::assertStringContainsString('https://bo.example.test/activate?token=opaque', $mail->text);
            self::assertStringContainsString('https://bo.example.test/activate?token=opaque', $mail->html);
        }
    }
}
