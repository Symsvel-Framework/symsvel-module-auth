<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Controller;

use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Attribute\Route;
use SymSvel\Module\Auth\Identity\EmailVerificationCompletion;
use SymSvel\Module\Auth\Identity\EmailVerificationDispatch;

/** App confirmation remains available without an authenticated session. */
final readonly class AppEmailVerificationController
{
    public function __construct(
        private EmailVerificationDispatch $dispatch,
        private EmailVerificationCompletion $completion,
    ) {
    }

    #[Route('/apiopen/auth/email-verification/request', name: 'symsvel_auth_app_verify_request', methods: ['POST'], format: 'json')]
    public function request(Request $request): JsonResponse
    {
        $body = self::json($request);
        if ($body instanceof JsonResponse) {
            return $body;
        }
        if (!is_string($body['email'] ?? null) || strlen($body['email']) > 254
            || filter_var(trim($body['email']), FILTER_VALIDATE_EMAIL) === false) {
            return self::answer(['error' => ['code' => 'invalid_request']], 400);
        }
        $locale = $body['locale'] ?? 'fr';
        if (!in_array($locale, ['fr', 'en'], true)) {
            return self::answer(['error' => ['code' => 'invalid_request']], 400);
        }

        // Uniform public response for unknown, verified and rate-limited accounts.
        $this->dispatch->dispatch(
            'app', trim($body['email']), $locale, (string) $request->getClientIp(),
            new \DateTimeImmutable('now', new \DateTimeZone('UTC')),
        );
        return self::answer(['status' => 'accepted'], 202);
    }

    #[Route('/apiopen/auth/email-verification/complete', name: 'symsvel_auth_app_verify_complete', methods: ['POST'], format: 'json')]
    public function complete(Request $request): JsonResponse
    {
        $body = self::json($request);
        if ($body instanceof JsonResponse) {
            return $body;
        }
        if (!is_string($body['token'] ?? null)
            || !preg_match('/^[A-Za-z0-9_-]{43}$/D', $body['token'])) {
            return self::answer(['error' => ['code' => 'invalid_request']], 400);
        }
        $success = $this->completion->complete(
            'app', $body['token'], new \DateTimeImmutable('now', new \DateTimeZone('UTC')),
        );
        return $success ? self::answer(['status' => 'completed'])
            : self::answer(['error' => ['code' => 'invalid_verification_token']], 400);
    }

    /** @return array<string, mixed>|JsonResponse */
    private static function json(Request $request): array|JsonResponse
    {
        if (!str_starts_with(strtolower($request->headers->get('Content-Type', '')), 'application/json')) {
            return self::answer(['error' => ['code' => 'unsupported_media_type']], 415);
        }
        $raw = $request->getContent();
        if (strlen($raw) > 8192) {
            return self::answer(['error' => ['code' => 'invalid_request']], 400);
        }
        try {
            $data = json_decode($raw, true, 8, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return self::answer(['error' => ['code' => 'invalid_request']], 400);
        }
        return is_array($data) && !array_is_list($data)
            ? $data : self::answer(['error' => ['code' => 'invalid_request']], 400);
    }

    private static function answer(array $payload, int $status = 200): JsonResponse
    {
        $response = new JsonResponse($payload, $status);
        $response->headers->set('Cache-Control', 'no-store');
        $response->headers->set('Pragma', 'no-cache');
        return $response;
    }
}
