<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Identity;

/** Implemented by Users, which retains ownership of App account state. */
interface AppInvitationIdentity
{
    public function activateInvitation(
        int $userId,
        string $emailHash,
        string $passwordHash,
        \DateTimeImmutable $now,
    ): bool;
}

