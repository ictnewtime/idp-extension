<?php

namespace NewTimeGroup\IdpClient\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Http;
use NewTimeGroup\IdpClient\IdpService;
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
        $idp_cookie_expiration = env("IDP_COOKIE_EXPIRATION_MIN", 60 * 24 * 30);
        $provider_id = $this->idpService->getClientId();
        $cookie_key = "idp_token_" . $provider_id;

        $token_from_url = $request->query("token");
        $token_cookie = $request->cookie($cookie_key) ?? ($_COOKIE[$cookie_key] ?? null);

        if (!$token_from_url && !$token_cookie) {
            $currentUrl = $request->fullUrl();
            Log::warning("REDIRECT: Token not found. Send user to IDP. Return URL: " . $currentUrl);
            return redirect()->away($this->idpService->getLoginUrl($currentUrl));
        }

        $token_to_validate = null;
        $isLocal = app()->environment("local") || $request->getHost() === "localhost";

        Log::info("isLocal: " . ($isLocal ? "true" : "false"));

        if ($token_from_url) {
            cookie()->queue($cookie_key, $token_from_url, $idp_cookie_expiration, "/", null, !$isLocal, true);
            $token_to_validate = $token_from_url;
            Log::info("token_from_url " . $token_from_url);
            return redirect($request->fullUrlWithoutQuery("token"));
        } else {
            $token_to_validate = $token_cookie;
        }

        $tokenParts = explode(".", $token_to_validate);

        // Un JWT valido ha sempre 3 parti. Estraiamo il payload (parte centrale).
        Log::info("tokenParts " . count($tokenParts));
        if (count($tokenParts) === 3) {
            $payload = json_decode(base64_decode($tokenParts[1]), true);
            $user_id = $payload["payload"]["user"]["id"] ?? null;

            if ($user_id) {
                // Recuperiamo URL e Timeout dalle variabili d'ambiente
                $idpUrlSessionCheck = env("IDP_URL_SESSION_CHECK");
                $timeout = env("IDP_REQUEST_TIMEOUT_SEC", 3);

                $queryParams = [
                    "ip_address" => $request->ip(),
                    "provider_id" => $provider_id,
                    "user_id" => $user_id,
                ];

                // Costruisci l'URL completo per il debug
                $fullUrl = $idpUrlSessionCheck . "?" . http_build_query($queryParams);
                Log::info("Invio richiesta a: " . $fullUrl);

                try {
                    // Invia la richiesta passando i parametri separatamente
                    $response = Http::timeout($timeout)->get($idpUrlSessionCheck, $queryParams);

                    Log::info("Risposta ricevuta: " . $response->status());

                    if ($response->status() === 404) {
                        // L'IdP ha risposto che la sessione è morta. Distruggiamo il cookie.
                        Log::warning("IDP Check: Session expired or not found. Force logout.");
                        cookie()->queue(cookie()->forget($cookie_key));
                        return redirect()->away($this->idpService->getLoginUrl($request->fullUrl()));
                    }

                    if ($response->successful()) {
                        // Se l'IP è cambiato e l'IdP ha creato una nuova sessione, restituisce il NUOVO token.
                        $newToken = $response->json("token");
                        if ($newToken && $newToken !== $token_to_validate) {
                            $token_to_validate = $newToken;
                            cookie()->queue(
                                $cookie_key,
                                $token_to_validate,
                                $idp_cookie_expiration,
                                "/",
                                null,
                                !$isLocal,
                                true,
                            );
                            Log::info("IDP Check: IP changed, new session token saved.");
                        }
                    }
                } catch (ConnectionException $e) {
                    // Fallback: L'IdP non risponde in tempo o è irraggiungibile.
                    Log::warning(
                        "IDP Check: Connection timeout, using local token validation. Error: " . $e->getMessage(),
                    );
                } catch (\Exception $e) {
                    Log::error("Errore generico durante IDP Check: " . $e->getMessage());
                }
            } else {
                // Se il token è formato bene ma NON contiene lo user_id
                Log::warning("IDP Check: Missing user_id in token payload. Destroying cookie.");
                cookie()->queue(cookie()->forget($cookie_key));
                return redirect()->refresh();
            }
        }

        // Validazione Locale Classica (Firma e Scadenza intrinseca)
        try {
            $claims = $this->idpService->validateToken($token_to_validate);
            return $next($request);
        } catch (TokenExpiredException $e) {
            Log::critical("Security Alert: Token expired locally.");
            cookie()->queue(cookie()->forget($cookie_key));
            return redirect()->refresh();
        } catch (InvalidSignatureException $e) {
            Log::critical("Security Alert: Invalid signature. IP: " . $request->ip());
            return abort(403, "Forbidden");
        } catch (\Exception $e) {
            Log::error("IDP Validation Error: " . $e->getMessage());
            return abort(401, "Authentication failed.");
        }
    }
}
