<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Token;

use Doctrine\DBAL\Connection;

/** Auth-owned inspection and removal of data linked to one App identity. */
final readonly class AppPrincipalSecurityData
{
    /** @var array<string, AppPrincipalSecurityContributor> */
    private array $contributors;

    /** @param iterable<AppPrincipalSecurityContributor> $contributors */
    public function __construct(private Connection $db, iterable $contributors = [])
    {
        $registered = [];
        foreach ($contributors as $contributor) {
            if (!$contributor instanceof AppPrincipalSecurityContributor) {
                throw new \InvalidArgumentException('Invalid App security-data contributor.');
            }
            $id = $contributor->moduleId();
            if (!preg_match('/^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$/D', $id) || isset($registered[$id])) {
                throw new \LogicException('Invalid or duplicate App security-data contributor.');
            }
            $registered[$id] = $contributor;
        }
        ksort($registered, SORT_STRING);
        $this->contributors = $registered;
    }

    public function hasActiveSession(int $userId, \DateTimeImmutable $now): bool
    {
        if ($userId < 1) throw new \InvalidArgumentException('Invalid App principal.');
        $stamp = $now->setTimezone(new \DateTimeZone('UTC'))->format('Y-m-d H:i:s.u');
        foreach (['access', 'refresh'] as $kind) {
            $sql = 'SELECT COUNT(*) FROM symsvel_auth_'.$kind.'_tokens WHERE context = ? AND principal_id = ? AND revoked_at IS NULL AND expires_at > ?';
            if ($kind === 'refresh') $sql .= ' AND used_at IS NULL';
            if ((int) $this->db->fetchOne($sql, ['app', $userId, $stamp]) > 0) return true;
        }
        return false;
    }

    /** The identity owner must already hold the account row lock. */
    public function erase(int $userId): void
    {
        if ($userId < 1 || !$this->db->isTransactionActive()) {
            throw new \LogicException('App security-data erasure requires the owner transaction.');
        }
        foreach ($this->contributors as $contributor) {
            $contributor->eraseAppPrincipal($userId);
        }
        foreach (['symsvel_auth_email_verification_tokens', 'symsvel_auth_password_reset_tokens', 'symsvel_auth_profile_email_changes', 'symsvel_auth_access_tokens', 'symsvel_auth_refresh_tokens'] as $table) {
            $this->db->delete($table, ['context' => 'app', 'principal_id' => $userId]);
        }
        $this->db->delete('symsvel_auth_app_invitations', ['principal_id' => $userId]);
    }
}
