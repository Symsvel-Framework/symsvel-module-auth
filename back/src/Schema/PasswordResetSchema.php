<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Schema;

use Doctrine\DBAL\Schema\Schema;

final class PasswordResetSchema
{
    public static function apply(Schema $schema): void
    {
        $table = $schema->createTable('symsvel_auth_password_reset_tokens');
        $table->addColumn('id', 'integer', ['autoincrement' => true]);
        $table->addColumn('context', 'string', ['length' => 8]);
        $table->addColumn('principal_id', 'integer');
        $table->addColumn('token_hash', 'string', ['length' => 64]);
        $table->addColumn('expires_at', 'datetime_immutable', ['precision' => 6]);
        $table->addColumn('created_at', 'datetime_immutable', ['precision' => 6]);
        $table->addColumn('used_at', 'datetime_immutable', ['precision' => 6, 'notnull' => false]);
        $table->setPrimaryKey(['id']);
        $table->addUniqueIndex(['token_hash'], 'uniq_symsvel_auth_reset_hash');
        $table->addIndex(['context', 'principal_id'], 'idx_symsvel_auth_reset_subject');
        $table->addIndex(['expires_at'], 'idx_symsvel_auth_reset_expiry');
    }
}
