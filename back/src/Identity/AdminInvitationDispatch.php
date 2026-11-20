<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Identity;

use SymSvel\Module\Auth\Service\AdminInvitationUrlResolver;
use SymSvel\Module\Auth\Token\AdminInvitationToken;
use SymSvel\Module\Auth\Token\DbalAdminInvitationStore;
use SymSvel\Module\Mails\Mail\ConfiguredMailSender;
use SymSvel\Module\Mails\Mail\RegisteredMailRenderer;

/** Internal only. The authorized Admins caller must provision and authorize the account. */
final readonly class AdminInvitationDispatch
{
    public function __construct(
        private AdminInvitationUrlResolver $urls,
        private DbalAdminInvitationStore $tokens,
        private RegisteredMailRenderer $renderer,
        private ConfiguredMailSender $sender,
    ) {}

    public function dispatch(int $adminId, string $email, string $locale, \DateTimeImmutable $now): void
    {
        if ($adminId < 1 || filter_var($email, FILTER_VALIDATE_EMAIL) === false || strlen($email) > 254) {
            throw new \InvalidArgumentException('Invalid BO administrator invitation.');
        }

        $url = $this->urls->resolve();
        $token = AdminInvitationToken::issue($now);
        $mail = $this->renderer->render('auth.bo.admin_invitation', $locale, [
            'invitationUrl' => $url.'?token='.rawurlencode($token->raw),
        ]);
        $this->tokens->save($adminId, $email, $token, $now);
        $this->sender->send($mail, $email);
    }
}
