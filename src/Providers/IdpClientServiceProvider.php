<?php

namespace NewTimeGroup\IdpClient\Providers;

use Illuminate\Container\Attributes\Log;
use Illuminate\Support\ServiceProvider;
use NewTimeGroup\IdpClient\IdpService;
use NewTimeGroup\IdpClient\Http\Middleware\IdpAuthMiddleware;

class IdpClientServiceProvider extends ServiceProvider
{
    public function register()
    {
        $configPath = __DIR__ . "/../config/idp-client.php";

        if (!file_exists($configPath)) {
            Log::error("Config file not found: " . $configPath);
            throw new \Exception("Config file not found: " . $configPath);
        }

        // If the file exists but doesn't return an array, log an error
        $configData = include $configPath;
        if (!is_array($configData)) {
            Log::error("Config file does not return an array: " . $configPath);
            throw new \Exception("Config file is invalid: " . $configPath);
        }

        // Merge the package configuration with the application's copy
        $this->mergeConfigFrom($configPath, "idp-client");

        // Bind of the IdpService to the service container for easy injection
        $this->app->singleton("idp-client", function ($app) {
            return new IdpService();
        });
    }

    public function boot()
    {
        // Publish of the configuration file to the application's config directory
        $this->publishes(
            [
                __DIR__ . "/../../config/idp-client.php" => config_path("idp-client.php"),
            ],
            "idp-client-config",
        );

        // Middleware registration
        $this->app["router"]->aliasMiddleware("idp.auth", IdpAuthMiddleware::class);
    }
}
