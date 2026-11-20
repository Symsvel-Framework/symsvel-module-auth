<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Tests\Token;

use Doctrine\DBAL\DriverManager;
use Doctrine\DBAL\Schema\Schema;
use PHPUnit\Framework\TestCase;
use SymSvel\Module\Auth\Schema\ProfileEmailChangeSchema;

/** Compiled migration bodies must not depend on imports discarded by Tooling. */
final class ProfileEmailChangeMigrationTest extends TestCase
{
    public function testModuleMigrationIsAutonomousAndMatchesTheRuntimeTable(): void
    {
        $source = dirname(__DIR__, 3).'/Migration/Version20261119000012.php';
        $content = file_get_contents($source);
        self::assertIsString($content);
        self::assertStringNotContainsString('use SymSvel\\Module\\', $content);
        self::assertStringNotContainsString('ProfileEmailChangeSchema::', $content);

        require_once $source;
        $migration = (new \ReflectionClass(\DoctrineMigrations\Version20261119000012::class))
            ->newInstanceWithoutConstructor();

        $actual = new Schema();
        $migration->up($actual);

        $expected = new Schema();
        ProfileEmailChangeSchema::apply($expected);

        $connection = DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]);
        self::assertSame(
            $expected->toSql($connection->getDatabasePlatform()),
            $actual->toSql($connection->getDatabasePlatform()),
        );

        $migration->down($actual);
        self::assertFalse($actual->hasTable('symsvel_auth_profile_email_changes'));
    }
}
