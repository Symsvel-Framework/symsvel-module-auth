<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Identity;

use SymSvel\Module\Auth\Token\TokenSubject;

/** Credential owner confirms only the mailbox presently assigned to its subject. */
interface EmailVerificationIdentity extends ContextOwnedIdentity
{
    public function confirmEmail(TokenSubject $subject, string $emailHash, \DateTimeImmutable $now): bool;
}
