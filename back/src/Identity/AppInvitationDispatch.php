<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Identity;

use SymSvel\Module\Auth\Service\AppInvitationUrlResolver;
use SymSvel\Module\Auth\Token\AppInvitationToken;
use SymSvel\Module\Auth\Token\DbalAppInvitationStore;
use SymSvel\Module\Mails\Mail\ConfiguredMailSender;
use SymSvel\Module\Mails\Mail\RegisteredMailRenderer;

/** Called only after Users' BO ACL authorizes the account invitation. */
final readonly class AppInvitationDispatch
{
    public function __construct(
        private AppInvitationUrlResolver $urls,
        private DbalAppInvitationStore $tokens,
        private RegisteredMailRenderer $renderer,
        private ConfiguredMailSender $sender,
    ) {}

    public function dispatch(int $userId, string $email, string $locale, \DateTimeImmutable $now): void
    {
        if ($userId < 1 || filter_var($email, FILTER_VALIDATE_EMAIL) === false || strlen($email) > 254) {
            throw new \InvalidArgumentException('Invalid App invitation.');
        }
        $url = $this->urls->resolve();
        $token = AppInvitationToken::issue($now);
        $mail = $this->renderer->render('auth.app.user_invitation', $locale, [
            'invitationUrl' => $url.'?token='.rawurlencode($token->raw),
        ]);
        $this->tokens->save($userId, $email, $token, $now);
        $this->sender->send($mail, $email);
    }
}

