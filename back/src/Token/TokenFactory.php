<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Token;

/**
 * Génère des secrets opaques. Seuls les empreintes SHA-256 doivent être persistées.
 * Ne jamais journaliser les valeurs raw.
 */
final readonly class TokenFactory
{
    public function __construct(private TokenPolicy $policy = new TokenPolicy())
    {
    }

    public function issue(string $context, ?string $familyId = null, ?\DateTimeImmutable $now = null): TokenPair
    {
        if (!in_array($context, ['bo', 'app'], true)) {
            throw new \InvalidArgumentException('Unknown authentication context.');
        }

        $now ??= new \DateTimeImmutable();
        $familyId ??= bin2hex(random_bytes(16));

        if (!preg_match('/^[a-f0-9]{32}$/D', $familyId)) {
            throw new \InvalidArgumentException('Invalid token family identifier.');
        }

        return new TokenPair(
            $context,
            $familyId,
            $this->createToken($now->modify('+'.$this->policy->accessTtl.' seconds')),
            $this->createToken($now->modify('+'.$this->policy->refreshTtl.' seconds')),
        );
    }

    private function createToken(\DateTimeImmutable $expiresAt): IssuedToken
    {
        $raw = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');

        return new IssuedToken($raw, hash('sha256', $raw), $expiresAt);
    }
}
