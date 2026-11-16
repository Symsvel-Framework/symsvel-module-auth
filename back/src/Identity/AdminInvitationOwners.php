<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Identity;

/** Resolve the single BO invitation identity owner without coupling Auth to Admins. */
final class AdminInvitationOwners
{
    private ?AdminInvitationIdentity $owner = null;

    /** @param iterable<AdminInvitationIdentity> $owners */
    public function __construct(iterable $owners)
    {
        foreach ($owners as $owner) {
            if ($this->owner !== null) {
                throw new \LogicException('Multiple BO administrator invitation owners.');
            }
            $this->owner = $owner;
        }
    }

    public function activate(int $adminId, string $emailHash, string $passwordHash, \DateTimeImmutable $now): bool
    {
        return $this->owner?->activateInvitation($adminId, $emailHash, $passwordHash, $now) ?? false;
    }
}
