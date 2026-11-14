<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Token;

use Doctrine\DBAL\Connection;

/**
 * Revokes only a family that owns BOTH presented BO tokens.
 * A refresh token from another session cannot terminate the access session.
 */
final readonly class BoSessionLogout
{
    public function __construct(private Connection $connection)
    {
    }

    public function logout(string $access, string $refresh, \DateTimeImmutable $now): bool
    {
        if (!preg_match('/^[A-Za-z0-9_-]{43}$/D', $access)
            || !preg_match('/^[A-Za-z0-9_-]{43}$/D', $refresh)) {
            return false;
        }

        return $this->connection->transactional(function () use ($access, $refresh, $now): bool {
            $row = $this->connection->fetchAssociative(
                'SELECT r.family_id, r.principal_id FROM symsvel_auth_refresh_tokens r '
                .'INNER JOIN symsvel_auth_access_tokens a '
                .'ON a.family_id = r.family_id AND a.context = r.context AND a.principal_id = r.principal_id '
                .'WHERE r.token_hash = ? AND a.token_hash = ? '
                .'AND r.context = ? AND r.revoked_at IS NULL AND r.used_at IS NULL '
                .'AND a.revoked_at IS NULL AND r.expires_at > ? AND a.expires_at > ?',
                [
                    hash('sha256', $refresh),
                    hash('sha256', $access),
                    'bo',
                    $now->setTimezone(new \DateTimeZone('UTC'))->format('Y-m-d H:i:s.u'),
                    $now->setTimezone(new \DateTimeZone('UTC'))->format('Y-m-d H:i:s.u'),
                ],
            );
            if ($row === false) {
                return false;
            }

            $timestamp = $now->setTimezone(new \DateTimeZone('UTC'))->format('Y-m-d H:i:s.u');
            foreach (['symsvel_auth_access_tokens', 'symsvel_auth_refresh_tokens'] as $table) {
                $this->connection->executeStatement(
                    'UPDATE '.$table.' SET revoked_at = ? WHERE context = ? AND family_id = ? AND principal_id = ? AND revoked_at IS NULL',
                    [$timestamp, 'bo', $row['family_id'], $row['principal_id']],
                );
            }

            return true;
        });
    }
}
