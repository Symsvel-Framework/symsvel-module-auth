<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Controller;

use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Attribute\Route;
use SymSvel\Module\Auth\Identity\EmailVerificationCompletion;

/**
 * Public BO token completion only. No account lookup or token is disclosed.
 * App routes must remain owned by the optional App installation.
 */
final readonly class EmailVerificationCompleteController
{
    public function __construct(private EmailVerificationCompletion $completion)
    {
    }

    #[Route('/apibo/auth/email-verification/complete', name: 'symsvel_auth_bo_email_verify_complete', methods: ['POST'], format: 'json')]
    public function bo(Request $request): JsonResponse
    {
        if (!str_starts_with(strtolower($request->headers->get('Content-Type', '')), 'application/json')) {
            return self::response(['error' => ['code' => 'unsupported_media_type', 'message' => 'JSON required.']], 415);
        }

        try {
            $payload = json_decode($request->getContent(), true, 8, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return self::response(['error' => ['code' => 'invalid_request', 'message' => 'Invalid request.']], 400);
        }

        if (!is_array($payload)
            || !is_string($payload['token'] ?? null)
            || !preg_match('/^[A-Za-z0-9_-]{43}$/D', $payload['token'])) {
            return self::response(['error' => ['code' => 'invalid_request', 'message' => 'Invalid request.']], 400);
        }

        $confirmed = $this->completion->complete(
            'bo',
            $payload['token'],
            new \DateTimeImmutable('now', new \DateTimeZone('UTC')),
        );

        return $confirmed
            ? self::response(['status' => 'completed'])
            : self::response(['error' => ['code' => 'invalid_verification_token', 'message' => 'Verification token invalid or expired.']], 400);
    }

    private static function response(array $data, int $status = 200): JsonResponse
    {
        $response = new JsonResponse($data, $status);
        $response->headers->set('Cache-Control', 'no-store');
        $response->headers->set('Pragma', 'no-cache');

        return $response;
    }
}
