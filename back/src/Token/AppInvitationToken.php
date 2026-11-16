<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Token;

/** A purpose-bound App invitation secret, never accepted as a reset token. */
final readonly class AppInvitationToken
{
    public function __construct(
        public string $raw,
        public string $hash,
        public \DateTimeImmutable $expiresAt,
    ) {
        if (!preg_match('/^[A-Za-z0-9_-]{43}$/D', $raw)
            || !hash_equals(hash('sha256', $raw), $hash)) {
            throw new \InvalidArgumentException('Invalid App invitation token.');
        }
    }

    public static function issue(\DateTimeImmutable $now, int $ttlSeconds = 3600): self
    {
        if ($ttlSeconds < 1) {
            throw new \InvalidArgumentException('Invalid invitation lifetime.');
        }
        $raw = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
        return new self($raw, hash('sha256', $raw), $now->modify('+'.$ttlSeconds.' seconds'));
    }

    public static function fingerprint(string $raw): ?string
    {
        return preg_match('/^[A-Za-z0-9_-]{43}$/D', $raw) ? hash('sha256', $raw) : null;
    }

