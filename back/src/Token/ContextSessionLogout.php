<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Token;

use Doctrine\DBAL\Connection;

/** Revokes a session only when both tokens belong to the same live family and context. */
final readonly class ContextSessionLogout
{
    public function __construct(private Connection $connection)
    {
    }

    public function logout(string $context, string $access, string $refresh, \DateTimeImmutable $now): bool
    {
        if (!in_array($context, ['bo', 'app'], true)
            || !preg_match('/^[A-Za-z0-9_-]{43}$/D', $access)
            || !preg_match('/^[A-Za-z0-9_-]{43}$/D', $refresh)) {
            return false;
        }

        return $this->connection->transactional(function () use ($context, $access, $refresh, $now): bool {
            $timestamp = $now->setTimezone(new \DateTimeZone('UTC'))->format('Y-m-d H:i:s.u');
            $row = $this->connection->fetchAssociative(
                'SELECT r.family_id, r.principal_id FROM symsvel_auth_refresh_tokens r '
                .'INNER JOIN symsvel_auth_access_tokens a '
                .'ON a.family_id = r.family_id AND a.context = r.context AND a.principal_id = r.principal_id '
                .'WHERE r.token_hash = ? AND a.token_hash = ? AND r.context = ? '
                .'AND r.revoked_at IS NULL AND r.used_at IS NULL AND a.revoked_at IS NULL '
                .'AND r.expires_at > ? AND a.expires_at > ?',
                [hash('sha256', $refresh), hash('sha256', $access), $context, $timestamp, $timestamp],
            );
            if ($row === false) {
                return false;
            }

            foreach (['symsvel_auth_access_tokens', 'symsvel_auth_refresh_tokens'] as $table) {
                $this->connection->executeStatement(
                    'UPDATE '.$table.' SET revoked_at = ? WHERE context = ? AND family_id = ? AND principal_id = ? AND revoked_at IS NULL',
                    [$timestamp, $context, $row['family_id'], $row['principal_id']],
                );
            }

            return true;
        });
    }
}
