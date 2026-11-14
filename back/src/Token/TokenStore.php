<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Token;

/**
 * Contrat de persistance. L'implémentation doit garantir une transaction
 * sérialisant la consommation d'un refresh token et ses effets.
 */
interface TokenStore
{
    /**
     * Exécute le callback dans une transaction BDD et annule tous les effets
     * si une exception est levée.
     *
     * @template T
     * @param callable(): T $operation
     * @return T
     */
    public function transaction(callable $operation): mixed;

    /** Recherche avec verrou exclusif sur le token ou protection équivalente. */
    public function lockRefresh(string $hash): ?RefreshTokenRecord;

    /**
     * Transition conditionnelle fresh -> used. Retourne false si une autre
     * transaction a déjà consommé/révoqué le token.
     */
    public function consumeRefresh(string $hash, \DateTimeImmutable $at): bool;

    public function savePair(TokenSubject $subject, TokenPair $pair, \DateTimeImmutable $at): void;

    public function revokeFamily(string $context, string $familyId, \DateTimeImmutable $at): void;

    public function revokeFamilyAccess(string $context, string $familyId, \DateTimeImmutable $at): void;
}
