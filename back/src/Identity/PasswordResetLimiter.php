<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Identity;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\Exception\UniqueConstraintViolationException;
use Symfony\Component\DependencyInjection\Attribute\Autowire;

/**
 * Durable, fail-closed fixed-window guard for password reset requests.
 * The future HTTP adapter must resolve the client IP through trusted proxies.
 */
final readonly class PasswordResetLimiter
{
    public function __construct(
        private Connection $connection,
        #[Autowire('%kernel.secret%')] private string $secret,
    ) {
        if (strlen($secret) < 16) {
            throw new \InvalidArgumentException('A strong application secret is required for reset rate limiting.');
        }
    }

    public function allow(string $context, string $identifier, string $clientIp, \DateTimeImmutable $now): bool
    {
        return $this->reserveRequest($context, $identifier, $clientIp, $now, 'identifier', 'ip');
    }

    /** Separate quota namespace for mailbox confirmation requests. */
    public function allowVerification(string $context, string $identifier, string $clientIp, \DateTimeImmutable $now): bool
    {
        return $this->reserveRequest($context, $identifier, $clientIp, $now, 'verify_id', 'verify_ip');
    }

    /** Dedicated quota for public account registrations. */
    public function allowRegistration(string $identifier, string $clientIp, \DateTimeImmutable $now): bool
    {
        return $this->reserveRequest('app', $identifier, $clientIp, $now, 'register_id', 'register_ip');
    }

    private function reserveRequest(
        string $context, string $identifier, string $clientIp, \DateTimeImmutable $now,
        string $identifierScope, string $ipScope,
    ): bool {

        if (!in_array($context, ['bo', 'app'], true)
            || trim($identifier) === '' || strlen($identifier) > 1024
            || filter_var($clientIp, FILTER_VALIDATE_IP) === false) {
            return false;
        }

        // Both reservations are committed together. If either bucket is already
        // occupied the whole attempt is denied, including unknown accounts.
        try {
            return $this->connection->transactional(function () use ($context, $identifier, $clientIp, $now, $identifierScope, $ipScope): bool {
                $this->reserve($context, $identifierScope, strtolower(trim($identifier)), 300, $now);
                $this->reserve($context, $ipScope, $clientIp, 10, $now);

                return true;
            });
        } catch (UniqueConstraintViolationException) {
            return false;
        }
    }

    private function reserve(
        string $context,
        string $scope,
        string $value,
        int $seconds,
        \DateTimeImmutable $now,
    ): void {
        $start = intdiv($now->getTimestamp(), $seconds) * $seconds;
        $hash = hash_hmac('sha256', $context."\0".$scope."\0".$value, $this->secret);

        $this->connection->insert('symsvel_auth_reset_limits', [
            'context' => $context,
            'scope' => $scope,
            'key_hash' => $hash,
            'window_start' => $start,
            'expires_at' => (new \DateTimeImmutable('@'.($start + $seconds)))->format('Y-m-d H:i:s.u'),
        ]);
    }
}
