<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Identity;

/** Resolve the sole optional App invitation owner without depending on Users. */
final class AppInvitationOwners
{
    private ?AppInvitationIdentity $owner = null;

    /** @param iterable<AppInvitationIdentity> $owners */
    public function __construct(iterable $owners)
    {
        foreach ($owners as $owner) {
            if ($this->owner !== null) throw new \LogicException('Multiple App invitation owners.');
            $this->owner = $owner;
        }
    }

    public function activate(int $userId, string $emailHash, string $hash, \DateTimeImmutable $now): bool
    {
        return $this->owner?->activateInvitation($userId, $emailHash, $hash, $now) ?? false;
    }
}

