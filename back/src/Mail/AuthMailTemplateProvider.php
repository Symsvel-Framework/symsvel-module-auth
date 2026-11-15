<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Mail;

use SymSvel\Module\Mails\Mail\MailTemplate;
use SymSvel\Module\Mails\Mail\MailTemplateProviderInterface;

/** Native password recovery messages for the two isolated Auth contexts. */
final readonly class AuthMailTemplateProvider implements MailTemplateProviderInterface
{
    public function templates(): iterable
    {
        foreach (['bo', 'app'] as $context) {
            $locales = [];
            foreach (['fr', 'en'] as $locale) {
                $prefix = sprintf('@Auth/mail/password-reset/%s/', $locale);
                $locales[$locale] = [
                    'subject' => $prefix.'subject.twig',
                    'html' => $prefix.'body.html.twig',
                    'text' => $prefix.'body.txt.twig',
                ];
            }
            yield new MailTemplate('auth.'.$context.'.password_reset', $locales, ['resetUrl']);

            $verificationLocales = [];
            foreach (['fr', 'en'] as $locale) {
                $prefix = sprintf('@Auth/mail/email-verification/%s/', $locale);
                $verificationLocales[$locale] = [
                    'subject' => $prefix.'subject.twig',
                    'html' => $prefix.'body.html.twig',
                    'text' => $prefix.'body.txt.twig',
                ];
            }
            yield new MailTemplate('auth.'.$context.'.email_verification', $verificationLocales, ['verificationUrl']);
        }
    }
}
