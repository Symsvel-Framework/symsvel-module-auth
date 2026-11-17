<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Controller;

use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Attribute\Route;
use SymSvel\Module\Auth\Browser\TrustedBoOrigin;
use SymSvel\Module\Auth\Identity\PasswordLogin;
use SymSvel\Module\Auth\Identity\SecondFactorChallenge;
use SymSvel\Module\Auth\Token\RefreshDecision;
use SymSvel\Module\Auth\Token\TokenLogout;
use SymSvel\Module\Auth\Token\TokenPair;
use SymSvel\Module\Auth\Token\TokenRotation;

/**
 * Browser-only BO transport. Only the short-lived access token reaches JS;
 * refresh secrets stay in a HttpOnly SameSite=Strict host-only cookie.
 * Only local HTTP in dev uses a non-Secure, non-__Host cookie.
 */
final readonly class BoBrowserSessionController
{
    private const COOKIE_HTTPS = '__Host-symsvel-bo-refresh';
    private const COOKIE_LOCAL = 'symsvel-bo-refresh-local';

    public function __construct(
        private TrustedBoOrigin $origin,
        private PasswordLogin $login,
        private TokenRotation $rotation,
        private TokenLogout $logout,
    ) {
    }

    #[Route('/apibo/auth/browser/login', name: 'symsvel_auth_browser_login', methods: ['POST'], format: 'json')]
    public function login(Request $request): JsonResponse
    {
        if (!$this->origin->accepts($request)) {
            return self::error(403, 'forbidden');
        }
        $payload = self::json($request);
        if ($payload === null || !is_string($payload['email'] ?? null)
            || !is_string($payload['password'] ?? null)
            || strlen($payload['email']) > 254 || strlen($payload['password']) > 4096) {
            return self::error(400, 'invalid_request');
        }
        $pair = $this->login->login(
            'bo', $payload['email'], $payload['password'],
            new \DateTimeImmutable('now', new \DateTimeZone('UTC')),
        );
        if ($pair instanceof SecondFactorChallenge) {
            // A previously authenticated browser must not retain an older
            // refresh cookie while a new login is awaiting a second factor.
            $previous = $request->cookies->get($this->cookieName($request));
            if (is_string($previous) && preg_match('/^[A-Za-z0-9_-]{43}$/D', $previous)) {
                $this->logout->logout($previous, 'bo', new \DateTimeImmutable('now', new \DateTimeZone('UTC')));
            }
            return $this->forget(self::response($pair->response(), 202), $request);
        }
        return $pair === null ? self::error(401, 'invalid_credentials') : $this->pairResponse($pair, $request);
    }

    #[Route('/apibo/auth/browser/second-factor', name: 'symsvel_auth_browser_second_factor', methods: ['POST'], format: 'json')]
    public function secondFactor(Request $request): JsonResponse
    {
        if (!$this->origin->accepts($request)) {
            return self::error(403, 'forbidden');
        }
        $payload = self::json($request);
        if ($payload === null || !is_string($payload['challenge'] ?? null)
            || !is_string($payload['code'] ?? null)) {
            return self::error(400, 'invalid_request');
        }
        $verified = $this->login->completeSecondFactor('bo', $payload['challenge'],
            $payload['code'], new \DateTimeImmutable('now', new \DateTimeZone('UTC')));
        if ($verified === null) {
            return self::error(401, 'invalid_second_factor');
        }
        return $this->pairResponse($verified->tokens, $request, $verified->recoveryCodes);
    }

    #[Route('/apibo/auth/browser/refresh', name: 'symsvel_auth_browser_refresh', methods: ['POST'], format: 'json')]
    public function refresh(Request $request): JsonResponse
    {
        if (!$this->origin->accepts($request)) {
            return self::error(403, 'forbidden');
        }
        $secret = $request->cookies->get($this->cookieName($request));
        if (!is_string($secret) || !preg_match('/^[A-Za-z0-9_-]{43}$/D', $secret)) {
            return $this->forget(self::error(401, 'invalid_session'), $request);
        }
        $result = $this->rotation->rotate($secret, 'bo', new \DateTimeImmutable('now', new \DateTimeZone('UTC')));
        if ($result->decision !== RefreshDecision::Rotate || $result->pair === null) {
            return $this->forget(self::error(401, 'invalid_session'), $request);
        }
        return $this->pairResponse($result->pair, $request);
    }

    #[Route('/apibo/auth/browser/logout', name: 'symsvel_auth_browser_logout', methods: ['POST'], format: 'json')]
    public function logout(Request $request): JsonResponse
    {
        if (!$this->origin->accepts($request)) {
            return self::error(403, 'forbidden');
        }
        $secret = $request->cookies->get($this->cookieName($request));
        if (is_string($secret) && preg_match('/^[A-Za-z0-9_-]{43}$/D', $secret)) {
            $this->logout->logout($secret, 'bo', new \DateTimeImmutable('now', new \DateTimeZone('UTC')));
        }
        return $this->forget(self::response([], 204), $request);
    }

    private function pairResponse(TokenPair $pair, Request $request, array $recoveryCodes = []): JsonResponse
    {
        $response = self::response([
            ...($recoveryCodes !== [] ? ['recovery_codes' => $recoveryCodes] : []),
            'access_token' => $pair->access->raw,
            'expires_at' => $pair->access->expiresAt->format(\DateTimeInterface::ATOM),
            'token_type' => 'Bearer',
        ]);
        $response->headers->setCookie($this->cookie($pair->refresh->raw, $pair->refresh->expiresAt, $request));
        return $response;
    }

    private function forget(JsonResponse $response, Request $request): JsonResponse
    {
        $response->headers->setCookie($this->cookie('', new \DateTimeImmutable('@1'), $request));
        return $response;
    }

    private function cookieName(Request $request): string
    {
        return $this->origin->usesLocalHttpCookie($request) ? self::COOKIE_LOCAL : self::COOKIE_HTTPS;
    }

    private function cookie(string $value, \DateTimeImmutable $expiry, Request $request): Cookie
    {
        $localHttp = $this->origin->usesLocalHttpCookie($request);
        return Cookie::create($this->cookieName($request))
            ->withValue($value)
            ->withExpires($expiry)
            ->withPath('/')
            ->withSecure(!$localHttp)
            ->withHttpOnly(true)
            ->withSameSite(Cookie::SAMESITE_STRICT);
    }

    /** @return array<string, mixed>|null */
    private static function json(Request $request): ?array
    {
        if (!str_starts_with(strtolower($request->headers->get('Content-Type', '')), 'application/json')) {
            return null;
        }
        $body = $request->getContent();
        if (strlen($body) > 8192) {
            return null;
        }
        try {
            $payload = json_decode($body, true, 8, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return null;
        }
        return is_array($payload) && !array_is_list($payload) ? $payload : null;
    }

    private static function error(int $status, string $code): JsonResponse
    {
        return self::response(['error' => ['code' => $code]], $status);
    }

    private static function response(array $body, int $status = 200): JsonResponse
    {
        $response = new JsonResponse($status === 204 ? null : $body, $status);
        $response->headers->set('Cache-Control', 'no-store');
        $response->headers->set('Pragma', 'no-cache');
        return $response;
    }
}
