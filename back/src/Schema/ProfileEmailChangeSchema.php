<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Schema;

use Doctrine\DBAL\Schema\Schema;

/** Transient pending mailbox changes, separate from initial verification. */
final class ProfileEmailChangeSchema
{
    public static function apply(Schema $schema): void
    {
        $table = $schema->createTable('symsvel_auth_profile_email_changes');
        $table->addColumn('id', 'integer', ['autoincrement' => true]);
        $table->addColumn('context', 'string', ['length' => 8]);
        $table->addColumn('principal_id', 'integer');
        $table->addColumn('old_email_hash', 'string', ['length' => 64]);
        $table->addColumn('new_email', 'string', ['length' => 254]);
        $table->addColumn('token_hash', 'string', ['length' => 64]);
        $table->addColumn('expires_at', 'datetime_immutable', ['precision' => 6]);
        $table->addColumn('created_at', 'datetime_immutable', ['precision' => 6]);
        $table->addColumn('used_at', 'datetime_immutable', ['precision' => 6, 'notnull' => false]);
        $table->setPrimaryKey(['id']);
        $table->addUniqueIndex(['token_hash'], 'uniq_symsvel_auth_profile_email_token');
        $table->addIndex(['context', 'principal_id'], 'idx_symsvel_auth_profile_email_subject');
        $table->addIndex(['expires_at'], 'idx_symsvel_auth_profile_email_expiry');
    }
}
