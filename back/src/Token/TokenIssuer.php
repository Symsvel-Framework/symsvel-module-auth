<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Token;

/**
 * Persists a new token family atomically.
 *
 * The caller MUST authenticate an enabled BO/App principal before invoking
 * this service. This class intentionally does not perform password checks.
 */
final readonly class TokenIssuer
{
    /** @var list<SessionIssuedListener> */
    private array $listeners;

    /** @param iterable<SessionIssuedListener> $listeners */
    public function __construct(
        private TokenStore $store,
        private TokenFactory $factory,
        iterable $listeners = [],
    ) {
        $registered = [];
        foreach ($listeners as $listener) {
            if (!$listener instanceof SessionIssuedListener) {
                throw new \LogicException('Invalid session-issued listener.');
            }
            $registered[] = $listener;
        }
        $this->listeners = $registered;
    }

    private function persist(TokenSubject $subject, \DateTimeImmutable $now): TokenPair
    {
        $pair = $this->factory->issue($subject->context, null, $now);
        $this->store->savePair($subject, $pair, $now);
        foreach ($this->listeners as $listener) {
            $listener->onSessionIssued($subject, $now);
        }

        return $pair;
    }

    /**
     * The interactive caller verifies an optional factor inside the SAME
     * transaction as session issuance. A false guard commits rate-limit and
     * challenge-attempt counters but never creates access/refresh tokens.
     *
     * @param callable(): bool $verifiedGuard
     */
    public function issueWhen(TokenSubject $subject, \DateTimeImmutable $now, callable $verifiedGuard): ?TokenPair
    {
        return $this->store->transaction(function () use ($subject, $now, $verifiedGuard): ?TokenPair {
            if ($verifiedGuard() !== true) {
                return null;
            }
            return $this->persist($subject, $now);
        });
    }

    public function issue(TokenSubject $subject, \DateTimeImmutable $now): TokenPair
    {
        return $this->store->transaction(function () use ($subject, $now): TokenPair {
            return $this->persist($subject, $now);
        });
    }
}
