<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Identity;

use SymSvel\Module\Auth\Token\DbalPasswordResetStore;
use SymSvel\Module\Auth\Token\PasswordResetToken;
use SymSvel\Module\Mails\Mail\ConfiguredMailSender;
use SymSvel\Module\Mails\Mail\RegisteredMailRenderer;

/**
 * Internal service, not an HTTP endpoint. The caller must enforce anti-abuse
 * limits and provide a reset page URL from trusted server configuration.
 */
final readonly class PasswordResetDispatch
{
    public function __construct(
        private ContextPasswordResetIdentity $identities,
        private DbalPasswordResetStore $resets,
        private RegisteredMailRenderer $renderer,
        private ConfiguredMailSender $sender,
    ) {
    }

    public function dispatch(
        string $context,
        string $identifier,
        string $locale,
        string $trustedResetPageUrl,
        \DateTimeImmutable $now,
    ): bool {
        if (!in_array($context, ['bo', 'app'], true)) {
            throw new \InvalidArgumentException('Invalid password reset context.');
        }

        // HTTP callers must never pass an origin copied from request headers or payload.
        $parts = parse_url($trustedResetPageUrl);
        if (!is_array($parts)
            || strtolower((string) ($parts['scheme'] ?? '')) !== 'https'
            || empty($parts['host'])
            || isset($parts['user']) || isset($parts['pass'])
            || isset($parts['query']) || isset($parts['fragment'])
            || preg_match('/[\r\n]/', $trustedResetPageUrl)) {
            throw new \InvalidArgumentException('Trusted HTTPS reset page URL required.');
        }

        $subject = $this->identities->find($context, $identifier);
        if ($subject === null) {
            return false;
        }

        $email = $this->identities->recoveryEmail($subject);
        if ($email === null) {
            return false;
        }

        $token = PasswordResetToken::issue($context, $now);
        $mail = $this->renderer->render(
            'auth.'.$context.'.password_reset',
            $locale,
            ['resetUrl' => $trustedResetPageUrl.'?token='.rawurlencode($token->raw)],
        );

        // A token must be durable before its delivery is attempted.
        // Sending failures propagate; an unsent token expires naturally.
        $this->resets->save($subject, $token, $now);
        $this->sender->send($mail, $email);

        return true;
    }
}
