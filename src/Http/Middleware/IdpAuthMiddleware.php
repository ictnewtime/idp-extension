<?php

namespace NewTimeGroup\IdpClient\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use NewTimeGroup\IdpClient\IdpService;
use Illuminate\Support\Facades\Log;
use NewTimeGroup\IdpClient\Exceptions\InvalidSignatureException;
use NewTimeGroup\IdpClient\Exceptions\TokenExpiredException;

class IdpAuthMiddleware
{
    protected $idpService;

    public function __construct(IdpService $idpService)
    {
        $this->idpService = $idpService;
    }

    public function handle(Request $request, Closure $next)
    {
        // Get the token from cookies (Laravel's cookie helper or directly from $_COOKIE)
        $cookie_key = "idp_token_" . $this->idpService->getClientId();
        $token = $request->cookie($cookie_key) ?? ($_COOKIE[$cookie_key] ?? null);

        // If the token is missing, redirect to IDP
        if (!$token) {
            $currentUrl = $request->fullUrl();
            return redirect()->away($this->idpService->getLoginUrl($currentUrl));
        }

        try {
            // Validate the token by checking its signature and expiration
            $claims = $this->idpService->validateToken($token);

            // Opzionale: pulire l'URL dal token per estetica
            // if ($request->has('token')) {
            //     return redirect($request->fullUrlWithoutQuery('token'));
            // }
            return $next($request);
        } catch (TokenExpiredException $e) {
            Log::critical("Security Alert: Token expired. ");
            // Remove the expired token cookie
            $cookie_key = "idp_token_" . $this->idpService->getClientId();
            setcookie($cookie_key, "", time() - 365 * 24 * 60 * 60, "/");
            return redirect()->refresh();
        } catch (InvalidSignatureException $e) {
            Log::critical("Security Alert: Invalid signature. IP: " . $request->ip());
            return abort(403, "Forbidden");
        } catch (\Exception $e) {
            Log::error("IDP Error: " . $e->getMessage());
            return abort(401, "Authentication failed.");
        }
    }
}
