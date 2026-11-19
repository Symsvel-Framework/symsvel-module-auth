<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Controller;

use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Attribute\Route;
use SymSvel\Module\Auth\Identity\ProfileEmailChangeCompletion;

/** Public completion: the secret link itself is the single-use proof of mailbox ownership. */
final readonly class ProfileEmailChangeCompleteController
{
    public function __construct(private ProfileEmailChangeCompletion $completion)
    {
    }

    #[Route('/apibo/auth/profile/email-change/complete', name: 'symsvel_auth_bo_profile_email_complete', methods: ['POST'], format: 'json')]
    public function bo(Request $request): JsonResponse
    {
        return $this->complete($request, 'bo');
    }

    #[Route('/apiopen/auth/profile/email-change/complete', name: 'symsvel_auth_app_profile_email_complete', methods: ['POST'], format: 'json')]
    public function app(Request $request): JsonResponse
    {
        return $this->complete($request, 'app');
    }

    private function complete(Request $request, string $context): JsonResponse
    {
        if (!str_starts_with(strtolower($request->headers->get('Content-Type', '')), 'application/json')
            || strlen($request->getContent()) > 1024) {
            return self::reply(['error' => ['code' => 'invalid_request']], 400);
        }
        try {
            $body = json_decode($request->getContent(), true, 4, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return self::reply(['error' => ['code' => 'invalid_request']], 400);
        }
        if (!is_array($body) || array_is_list($body) || count($body) !== 1
            || !is_string($body['token'] ?? null)
            || !preg_match('/^[A-Za-z0-9_-]{43}$/D', $body['token'])) {
            return self::reply(['error' => ['code' => 'invalid_request']], 400);
        }
        $completed = $this->completion->complete(
            $context, $body['token'], new \DateTimeImmutable('now', new \DateTimeZone('UTC')),
        );
        return $completed ? self::reply(['status' => 'completed'])
            : self::reply(['error' => ['code' => 'invalid_verification_token']], 400);
    }

    private static function reply(array $body, int $status = 200): JsonResponse
    {
        $response = new JsonResponse($body, $status);
        $response->headers->set('Cache-Control', 'no-store');
        $response->headers->set('Pragma', 'no-cache');
        return $response;
    }
}
