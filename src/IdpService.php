<?php

namespace NewTimeGroup\IdpClient;

use DateTimeZone;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Constraint\LooseValidAt;
use Lcobucci\Clock\SystemClock;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Http;
use NewTimeGroup\IdpClient\Exceptions\InvalidSignatureException;
use NewTimeGroup\IdpClient\Exceptions\TokenExpiredException;

class IdpService
{
    protected $config;

    public function __construct()
    {
        // Load the configuration from the config/idp-client.php file
        $this->config = Config::get("idp-client");
    }

    public function getClientId()
    {
        return $this->config["client_id"];
    }

    /**
     * Generates the login URL for the IDP, including the provider_id and optional redirect_to parameters.
     */
    public function getLoginUrl(?string $currentUrl = null)
    {
        $login_url = rtrim($this->config["login_url"], "/");
        $clientId = $this->config["client_id"];
        $url = $login_url . "?provider_id=" . $clientId;
        // If your IDP supports a parameter like 'return_to' or 'redirect_url',
        // you can use it to redirect back after login
        // Assure that your IDP can handle a parameter like 'return_to' or 'redirect_url'
        // to redirect back after login
        if ($currentUrl) {
            $url .= "&redirect_to=" . urlencode($currentUrl);
        }

        return $url;
    }

    /**
     * Validates a JWT token by checking its signature and expiration.
     * Returns the token claims if valid, or null if invalid.
     */
    public function validateToken(string $jwtString)
    {
        $secret = $this->config["client_secret"];
        // Configure Lcobucci library for token validation (Symmetric HS256)
        $configuration = Configuration::forSymmetricSigner(new Sha256(), InMemory::plainText($secret));

        // Signature validity and token expiration checks
        $signedWith = new SignedWith($configuration->signer(), $configuration->signingKey());
        // Use a loose valid at constraint to allow for some clock skew (e.g., 5 seconds)
        // LooseValidAt want for second parameter null or DateInterval
        $leeway = new \DateInterval("PT0S"); // 0 secondi di tolleranza
        $validAt = new LooseValidAt(SystemClock::fromSystemTimezone(), $leeway);

        // Check token signature and expiration
        $token = $configuration->parser()->parse($jwtString);

        // Check token expiration
        if (!$configuration->validator()->validate($token, $validAt)) {
            // dd("valid at", $validAt);
            throw new TokenExpiredException("Token expired.");
        }
        if (!$configuration->validator()->validate($token, $signedWith)) {
            throw new InvalidSignatureException("Invalid signature.");
        }

        // Return claims as array
        return $token->claims()->all();
    }

    public function getRoles(string $token): array
    {
        $tokenParts = explode(".", $token);

        if (count($tokenParts) === 3) {
            $payload = json_decode(base64_decode($tokenParts[1]), true);
            return $payload["payload"]["roles"] ?? [];
        }

        return [];
    }

    /**
     * HELPER: Verifica se l'utente ha un ruolo specifico
     */
    public function hasRole(string $token, string $roleName): bool
    {
        $roles = $this->getRoles($token);

        foreach ($roles as $role) {
            if (isset($role["name"]) && $role["name"] === $roleName) {
                return true;
            }
        }
        return false;
    }

    /**
     * LOGOUT (Single Logout)
     * Avvisa l'IdP di distruggere la sessione e pulisce il cookie locale.
     */
    public function logout(Request $request)
    {
        Log::info("--- INIZIO PROCESSO DI LOGOUT (Client) ---");

        $provider_id = $this->getClientId();
        $cookie_key = "idp_token_" . $provider_id;
        $token = $request->cookie($cookie_key);

        Log::info("Provider ID: " . $provider_id);
        Log::info("Cookie Key: " . $cookie_key);
        Log::info("Token trovato nel cookie? " . ($token ? "SI" : "NO"));

        if ($token) {
            $tokenParts = explode(".", $token);
            Log::info("Token diviso in " . count($tokenParts) . " parti.");

            if (count($tokenParts) === 3) {
                $payload = json_decode(base64_decode($tokenParts[1]), true);
                $user_id = $payload["payload"]["user"]["id"] ?? null;

                Log::info("User ID estratto dal token: " . ($user_id ?? "NULL"));

                if ($user_id) {
                    // Chiamata server-to-server per distruggere la sessione sull'IdP
                    $idpLogoutUrl = env("IDP_URL_LOGOUT");
                    $timeout = env("IDP_REQUEST_TIMEOUT_SEC", 3);

                    Log::info("URL per logout server-to-server: " . $idpLogoutUrl);

                    try {
                        Log::info("Invio POST all'IdP per distruggere la sessione DB...");
                        $response = Http::timeout($timeout)->post($idpLogoutUrl, [
                            "provider_id" => $provider_id,
                            "user_id" => $user_id,
                        ]);
                        Log::info("Risposta riceuta dall'IdP: " . $response->status());
                        // Log::info("Body risposta IdP: " . $response->body());
                    } catch (\Exception $e) {
                        Log::error("IDP Logout failed to reach server: " . $e->getMessage());
                    }
                }
            } else {
                Log::warning("Il token non ha 3 parti, formato non valido.");
            }
        }

        // 2. Distruggiamo il cookie locale
        Log::info("Preparazione distruzione cookie locale: " . $cookie_key);
        $cookie = cookie()->forget($cookie_key);

        // 3. Rimandiamo l'utente alla pagina di logout dell'IdP (o alla home locale)
        $returnUrl = url("/");
        $redirectUrl = $this->getLogoutUrl($returnUrl);

        Log::info("Redirect finale impostato verso: " . $redirectUrl);
        Log::info("--- FINE PROCESSO DI LOGOUT ---");

        return redirect($redirectUrl)->withCookie($cookie);
    }

    public function getLogoutUrl(string $returnUrl): string
    {
        $idpBaseUrl = env("IDP_URL");
        $providerId = $this->getClientId();

        // Passiamo anche il provider_id in query string
        return $idpBaseUrl . "/sso/logout?provider_id=" . $providerId . "&redirect_to=" . urlencode($returnUrl);
    }
}
