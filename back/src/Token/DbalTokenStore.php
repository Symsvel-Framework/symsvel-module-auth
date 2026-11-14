<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Token;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\Platforms\SQLitePlatform;

/**
 * Stockage DBAL. SQLite acquiert un verrou d'écriture avant de lire le refresh ;
 * les autres moteurs utilisent SELECT FOR UPDATE.
 */
final class DbalTokenStore implements TokenStore, AccessTokenLookup
{
    public function __construct(private readonly Connection $connection)
    {
    }

    public function transaction(callable $operation): mixed
    {
        if ($this->connection->getDatabasePlatform() instanceof SQLitePlatform) {
            if ($this->connection->getTransactionNestingLevel() !== 0) {
                throw new \LogicException('SQLite token rotation requires an outermost transaction.');
            }
            // DBAL transaction state must stay synchronized with the driver.
            $this->connection->beginTransaction();
            try {
                $result = $operation();
                $this->connection->commit();

                return $result;
            } catch (\Throwable $exception) {
                if ($this->connection->isTransactionActive()) {
                    $this->connection->rollBack();
                }
                throw $exception;
            }
        }

        return $this->connection->transactional($operation);
    }


    public function findAccessByHash(string $hash): ?AccessTokenRecord
    {
        $row = $this->connection->fetchAssociative(
            'SELECT context, principal_id, expires_at, revoked_at FROM symsvel_auth_access_tokens WHERE token_hash = ?',
            [$hash],
        );
        if ($row === false) {
            return null;
        }

        return new AccessTokenRecord(
            new TokenSubject($row['context'], (int) $row['principal_id']),
            new \DateTimeImmutable($row['expires_at'], new \DateTimeZone('UTC')),
            $row['revoked_at'] === null ? null : new \DateTimeImmutable($row['revoked_at'], new \DateTimeZone('UTC')),
        );
    }

    public function lockRefresh(string $hash): ?RefreshTokenRecord
    {
        $sql = 'SELECT context, principal_id, family_id, expires_at, used_at, revoked_at FROM symsvel_auth_refresh_tokens WHERE token_hash = ?';
        if ($this->connection->getDatabasePlatform() instanceof SQLitePlatform) {
            // A deferred SQLite transaction must acquire its writer lock BEFORE
            // reading the refresh. Otherwise two readers may both observe a
            // fresh token and race when upgrading their read transactions.
            // The no-op update changes no logical token state.
            $this->connection->executeStatement(
                'UPDATE symsvel_auth_refresh_tokens SET token_hash = token_hash WHERE token_hash = ?',
                [$hash],
            );
        } else {
            $sql .= ' FOR UPDATE';
        }
        $row = $this->connection->fetchAssociative($sql, [$hash]);
        if ($row === false) {
            return null;
        }

        return new RefreshTokenRecord(
            new TokenSubject($row['context'], (int) $row['principal_id']),
            new RefreshTokenState(
                $row['context'],
                $row['family_id'],
                new \DateTimeImmutable($row['expires_at'], new \DateTimeZone('UTC')),
                $row['used_at'] === null ? null : new \DateTimeImmutable($row['used_at'], new \DateTimeZone('UTC')),
                $row['revoked_at'] === null ? null : new \DateTimeImmutable($row['revoked_at'], new \DateTimeZone('UTC')),
            ),
        );
    }

    public function consumeRefresh(string $hash, \DateTimeImmutable $at): bool
    {
        return $this->connection->executeStatement(
            'UPDATE symsvel_auth_refresh_tokens SET used_at = ? WHERE token_hash = ? AND used_at IS NULL AND revoked_at IS NULL AND expires_at > ?',
            [$this->timestamp($at), $hash, $this->timestamp($at)],
        ) === 1;
    }

    public function savePair(TokenSubject $subject, TokenPair $pair, \DateTimeImmutable $at): void
    {
        if ($subject->context !== $pair->context) {
            throw new \InvalidArgumentException('Token pair context mismatch.');
        }

        foreach (['access' => 'symsvel_auth_access_tokens', 'refresh' => 'symsvel_auth_refresh_tokens'] as $kind => $table) {
            $token = $kind === 'access' ? $pair->access : $pair->refresh;
            $this->connection->insert($table, [
                'context' => $subject->context,
                'principal_id' => $subject->id,
                'family_id' => $pair->familyId,
                'token_hash' => $token->hash,
                'expires_at' => $this->timestamp($token->expiresAt),
                'created_at' => $this->timestamp($at),
            ]);
        }
    }

    public function revokeFamily(string $context, string $familyId, \DateTimeImmutable $at): void
    {
        foreach (['symsvel_auth_access_tokens', 'symsvel_auth_refresh_tokens'] as $table) {
            $this->connection->executeStatement(
                'UPDATE '.$table.' SET revoked_at = ? WHERE context = ? AND family_id = ? AND revoked_at IS NULL',
                [$this->timestamp($at), $context, $familyId],
            );
        }
    }

    public function revokeFamilyAccess(string $context, string $familyId, \DateTimeImmutable $at): void
    {
        $this->connection->executeStatement(
            'UPDATE symsvel_auth_access_tokens SET revoked_at = ? WHERE context = ? AND family_id = ? AND revoked_at IS NULL',
            [$this->timestamp($at), $context, $familyId],
        );
    }

    public function revokeSubject(TokenSubject $subject, \DateTimeImmutable $at): void
    {
        foreach (['symsvel_auth_access_tokens', 'symsvel_auth_refresh_tokens'] as $table) {
            $this->connection->executeStatement(
                'UPDATE '.$table.' SET revoked_at = ? WHERE context = ? AND principal_id = ? AND revoked_at IS NULL',
                [$this->timestamp($at), $subject->context, $subject->id],
            );
        }
    }

    private function timestamp(\DateTimeImmutable $date): string
    {
        return $date->setTimezone(new \DateTimeZone('UTC'))->format('Y-m-d H:i:s.u');
    }
}
