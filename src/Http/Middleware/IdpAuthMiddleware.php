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
        $provider_id = $this->idpService->getClientId();
        $cookie_key = "idp_token_" . $provider_id;

        $token_url = $request->query("token");
        $token_cookie = $request->cookie($cookie_key) ?? ($_COOKIE[$cookie_key] ?? null);

        if (!$token_url && !$token_cookie) {
            $currentUrl = $request->fullUrl();
            Log::warning("REDIRECT: Token not forund. Ssend user to IDP. Return URL: " . $currentUrl);
            return redirect()->away($this->idpService->getLoginUrl($currentUrl));
        }

        $token_to_validate = null;
        if ($token_url) {
            $isLocal = app()->environment("local") || $request->getHost() === "localhost";

            cookie()->queue($cookie_key, $token_url, 60 * 24, "/", null, !$isLocal, true);

            // use url token for the validation
            $token_to_validate = $token_url;

            // Clear torken from the url
            return redirect($request->fullUrlWithoutQuery("token"));
        } else {
            $token_to_validate = $token_cookie;
        }

        try {
            $claims = $this->idpService->validateToken($token_to_validate);
            return $next($request);
        } catch (TokenExpiredException $e) {
            Log::critical("Security Alert: Token expired.");
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
