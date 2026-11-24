<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Tests\Unit;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SymSvel\Module\Auth\Identity\NewPasswordPolicy;

final class NewPasswordPolicyTest extends TestCase
{
    #[DataProvider('passwords')]
    public function testPolicy(string $password, bool $expected): void
    {
        self::assertSame($expected, NewPasswordPolicy::accepts($password));
    }

    public static function passwords(): iterable
    {
        yield 'valid minimum' => ['Abcdefghij1!', true];
        yield 'unicode' => ['Éa1!éééééééé', true];
        yield 'too short' => ['Abcdefghi1!', false];
        yield 'no lowercase' => ['ABCDEFGHIJK1!', false];
        yield 'no uppercase' => ['abcdefghijk1!', false];
        yield 'no digit' => ['Abcdefghijk!', false];
        yield 'no symbol' => ['Abcdefghijk1', false];
        yield 'whitespace is not a symbol' => ["Abcdefghij1\n", false];
        yield 'bytes are not characters' => ['Éa1!ééééééé', false];
        yield 'limit' => ['aB9!'.str_repeat('x', 1020), true];
        yield 'over limit' => ['aB9!'.str_repeat('x', 1021), false];
        yield 'null byte' => ["Abcdefghij1!\0", false];
        yield 'invalid UTF-8' => ["Abcdefghij1!\xFF", false];
    }
}
