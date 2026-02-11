<?php

namespace NewTimeGroup\IdpClient;

use DateTimeZone;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Constraint\LooseValidAt;
use Lcobucci\Clock\SystemClock;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Log;
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
}
