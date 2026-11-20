<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Tests\Token;

use SymSvel\Module\Auth\Token\RefreshTokenRecord;
use SymSvel\Module\Auth\Token\TokenPair;
use SymSvel\Module\Auth\Token\TokenStore;
use SymSvel\Module\Auth\Token\TokenSubject;

final class InMemoryTokenStore implements TokenStore
{
    public ?RefreshTokenRecord $record = null;
    public array $operations = [];
    public int $transactions = 0;
    public bool $consumeSucceeds = true;

    public function transaction(callable $operation): mixed
    {
        ++$this->transactions;

        return $operation();
    }

    public function lockRefresh(string $hash): ?RefreshTokenRecord
    {
        $this->operations[] = 'lock';

        return $this->record;
    }

    public function consumeRefresh(string $hash, \DateTimeImmutable $at): bool
    {
        $this->operations[] = 'consume';

        return $this->consumeSucceeds;
    }

    public function savePair(TokenSubject $subject, TokenPair $pair, \DateTimeImmutable $at): void
    {
        $this->operations[] = 'save';
    }

    public function revokeFamily(string $context, string $familyId, \DateTimeImmutable $at): void
    {
        $this->operations[] = 'revoke_family';
    }

    public function revokeSubject(TokenSubject $subject, \DateTimeImmutable $at): void
    {
        $this->operations[] = 'revoke_subject';
    }

    public function revokeFamilyAccess(string $context, string $familyId, \DateTimeImmutable $at): void
    {
        $this->operations[] = 'revoke_access';
    }
}
