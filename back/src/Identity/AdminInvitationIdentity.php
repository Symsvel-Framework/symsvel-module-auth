<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Identity;

/** Owned by Admins: atomically set the initial password and verify the invited mailbox. */
interface AdminInvitationIdentity
{
    /**
     * Must update only an eligible, not-yet-activated BO admin whose current
     * e-mail matches the invitation fingerprint. Uses the host DBAL connection.
     */
    public function activateInvitation(
        int $adminId,
        string $emailHash,
        string $passwordHash,
        \DateTimeImmutable $now,
    ): bool;
}
