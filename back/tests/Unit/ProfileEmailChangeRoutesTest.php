<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Attribute\Route;
use SymSvel\Module\Auth\Controller\ProfileEmailChangeCompleteController;
use SymSvel\Module\Auth\Service\AuthPageUrls;

final class ProfileEmailChangeRoutesTest extends TestCase
{
    public function testBoAndAppCompletionsAreContextIsolated(): void
    {
        foreach ([
            'bo' => '/apibo/auth/profile/email-change/complete',
            'app' => '/apiopen/auth/profile/email-change/complete',
        ] as $method => $path) {
            $attributes = (new \ReflectionMethod(ProfileEmailChangeCompleteController::class, $method))
                ->getAttributes(Route::class);
            self::assertCount(1, $attributes);
            self::assertSame($path, $attributes[0]->getArguments()[0]);
            self::assertSame(['POST'], $attributes[0]->getArguments()['methods']);
        }
        $urls = new AuthPageUrls('dev', 'example.test');
        self::assertSame('http://bo.example.test/verify-email-change', $urls->forPage('bo', 'change-email'));
        self::assertSame('http://app.example.test/verify-email-change', $urls->forPage('app', 'change-email'));
    }

    public function testPublicCompletionRejectsMalformedSecretWithoutUsingService(): void
    {
        $controller = (new \ReflectionClass(ProfileEmailChangeCompleteController::class))
            ->newInstanceWithoutConstructor();
        $wrong = Request::create('/apibo/auth/profile/email-change/complete', 'POST');
        self::assertSame(400, $controller->bo($wrong)->getStatusCode());
        $invalid = Request::create('/apiopen/auth/profile/email-change/complete', 'POST', [], [], [], [
            'CONTENT_TYPE' => 'application/json',
        ], '{"token":"too-short"}');
        self::assertSame(400, $controller->app($invalid)->getStatusCode());
    }
}
