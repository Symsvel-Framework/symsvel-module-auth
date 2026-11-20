<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Identity;

use SymSvel\Module\Auth\Service\EmailVerificationUrlResolver;
use SymSvel\Module\Auth\Token\DbalEmailVerificationStore;
use SymSvel\Module\Auth\Token\EmailVerificationToken;
use SymSvel\Module\Mails\Mail\ConfiguredMailSender;
use SymSvel\Module\Mails\Mail\RegisteredMailRenderer;

/** Internal dispatch only; future HTTP adapter must resolve its client IP safely. */
final readonly class EmailVerificationDispatch
{
    public function __construct(
        private PasswordResetLimiter $limiter,
        private EmailVerificationUrlResolver $urls,
        private ContextPasswordResetIdentity $subjects,
        private ContextEmailVerificationIdentity $identities,
        private DbalEmailVerificationStore $tokens,
        private RegisteredMailRenderer $renderer,
        private ConfiguredMailSender $sender,
    ) {
    }

    public function dispatch(
        string $context,
        string $identifier,
        string $locale,
        string $clientIp,
        \DateTimeImmutable $now,
    ): bool {
        if (!in_array($context, ['bo', 'app'], true)) {
            throw new \InvalidArgumentException('Invalid email verification context.');
        }

        $verificationPageUrl = $this->urls->forContext($context);
        if (!$this->limiter->allowVerification($context, $identifier, $clientIp, $now)) {
            return false;
        }

        $subject = $this->subjects->find($context, $identifier);
        if ($subject === null) {
            return false;
        }

        $email = $this->identities->pendingEmail($subject);
        if ($email === null) {
            return false;
        }

        $token = EmailVerificationToken::issue($context, $now);
        $mail = $this->renderer->render(
            'auth.'.$context.'.email_verification',
            $locale,
            ['verificationUrl' => $verificationPageUrl.'?token='.rawurlencode($token->raw)],
        );

        $this->tokens->save($subject, $email, $token, $now);
        $this->sender->send($mail, $email);

        return true;
    }
}
