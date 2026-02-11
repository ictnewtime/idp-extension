# Zanichelli IDP Laravel Extension packages

This is Laravel package to use with laravel-jwt-idp (Github: https://github.com/ZanichelliEditore/laravel-jwt-idp).

## How to integrate package in your project

### Step 1 - Install by Composer

```bash
composer require ictnewtime/idp-extensions
```

### Step 2 - Configure .env file

Aggiungere queste variabili d' ambiente enll' .env

```
# IDP
IDP_CLIENT_ID=<ID sull' idp del provider>
IDP_URL="http://localhost:8001"
IDP_URL_LOGIN="http://localhost:8001/loginForm"
IDP_CLIENT_SECRET=<32-alfanumeric-string>
```

### Step 3 - Add laravel configuration

Edit `config/auth.php` as follow:

```php
// ...
'providers' => [
    'users' => [
        'driver' => 'eloquent',
        'model' => env('AUTH_MODEL', App\Models\User::class),
        // ...
        IdpClientServiceProvider::class, // <- add this
    ],
```

Edit `bootstrap/providers.php` as follow:

```php
<?php

return [
    App\Providers\AppServiceProvider::class,
    App\Providers\FortifyServiceProvider::class,
    NewTimeGroup\IdpClient\Providers\IdpClientServiceProvider::class, // <- add this
];
```
