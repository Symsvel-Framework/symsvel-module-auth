<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Identity;

use SymSvel\Module\Auth\Service\AuthPageUrls;
use SymSvel\Module\Auth\Token\DbalProfileEmailChangeStore;
use SymSvel\Module\Auth\Token\EmailVerificationToken;
use SymSvel\Module\Auth\Token\TokenSubject;
use SymSvel\Module\Mails\Mail\ConfiguredMailSender;
use SymSvel\Module\Mails\Mail\RegisteredMailRenderer;

/** Send one confirmation link to the new mailbox, leaving the old one untouched. */
final readonly class ProfileEmailChangeDispatch
{
    public function __construct(
        private AuthPageUrls $pages,
        private PasswordResetLimiter $limiter,
        private DbalProfileEmailChangeStore $store,
        private RegisteredMailRenderer $renderer,
        private ConfiguredMailSender $sender,
    ) {
    }

    public function dispatch(
        TokenSubject $subject,
        string $oldEmail,
        string $newEmail,
        string $locale,
        string $clientIp,
        \DateTimeImmutable $now,
    ): bool {
        $old = strtolower(trim($oldEmail));
        $new = strtolower(trim($newEmail));
        if (strlen($new) > 254 || filter_var($new, FILTER_VALIDATE_EMAIL) === false
            || filter_var($old, FILTER_VALIDATE_EMAIL) === false
            || $old === $new || !in_array($locale, ['fr', 'en'], true)) {
            return false;
        }
        // Never use the HTTP Host header or a user-provided callback URL.
        $url = $this->pages->forPage($subject->context, 'change-email');
        if (!$this->limiter->allowVerification($subject->context, $new, $clientIp, $now)) {
            return false;
        }

        $token = EmailVerificationToken::issue($subject->context, $now);
        $mail = $this->renderer->render(
            'auth.'.$subject->context.'.email_verification',
            $locale,
            ['verificationUrl' => $url.'?token='.rawurlencode($token->raw)],
        );
        $this->store->save($subject, $old, $new, $token, $now);
        $this->sender->send($mail, $new);

        return true;
    }
}
