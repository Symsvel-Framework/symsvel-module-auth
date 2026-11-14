<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Schema;

use Doctrine\DBAL\Schema\Schema;

/**
 * Définition portable pour le compilateur de migrations Schema de SymSvel.
 */
final class AuthTokenSchema
{
    public static function apply(Schema $schema): void
    {
        foreach (['access', 'refresh'] as $kind) {
            $table = $schema->createTable('symsvel_auth_'.$kind.'_tokens');
            $table->addColumn('id', 'integer', ['autoincrement' => true]);
            $table->addColumn('context', 'string', ['length' => 8]);
            $table->addColumn('principal_id', 'integer');
            $table->addColumn('family_id', 'string', ['length' => 32]);
            $table->addColumn('token_hash', 'string', ['length' => 64]);
            $table->addColumn('expires_at', 'datetime_immutable', ['precision' => 6]);
            $table->addColumn('created_at', 'datetime_immutable', ['precision' => 6]);
            $table->addColumn('revoked_at', 'datetime_immutable', ['precision' => 6, 'notnull' => false]);
            if ($kind === 'refresh') {
                $table->addColumn('used_at', 'datetime_immutable', ['precision' => 6, 'notnull' => false]);
            }
            $table->setPrimaryKey(['id']);
            $table->addUniqueIndex(['token_hash'], 'uniq_symsvel_auth_'.$kind.'_hash');
            $table->addIndex(['context', 'family_id'], 'idx_symsvel_auth_'.$kind.'_family');
            $table->addIndex(['expires_at'], 'idx_symsvel_auth_'.$kind.'_expiry');
        }
    }
}
