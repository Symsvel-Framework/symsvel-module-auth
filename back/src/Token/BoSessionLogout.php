<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Token;

use Doctrine\DBAL\Connection;

/** Retains the BO-facing contract while sharing context-scoped revocation with App. */
final readonly class BoSessionLogout
{
    public function __construct(private Connection $connection)
    {
    }

    public function logout(string $access, string $refresh, \DateTimeImmutable $now): bool
    {
        return (new ContextSessionLogout($this->connection))->logout('bo', $access, $refresh, $now);
    }
}
