# Zanichelli IDP Laravel Extension packages

This is Laravel package to use with laravel-jwt-idp (Github: https://github.com/ZanichelliEditore/laravel-jwt-idp).

## How to integrate package in your project

### Step 1 - Install Vendor

1. Modifica il composer.json

```json
{
    "$schema": "https://getcomposer.org/schema.json",
    "name": "laravel/vue-starter-kit",
    "type": "project",
    // ... (altre stringhe)

    "repositories": [
        {
            "type": "vcs",
            "url": "https://github.com/ictnewtime/idp-extension.git"
        }
    ],

    "require": {
        "ictnewtime/idp-extension": "dev-master",
        "php": "^8.2"
    }
    // ... resto del file
}
```

2. Crea il file auth.json

```json
{
    "http-basic": {
        "gitea.newtimegroup.it": {
            "username": "tuo_username",
            "password": "il_tuo_token_di_accesso_personale"
        }
    },
    // oppure
    "github-oauth": {
        "github.com": "ghp_il_tuo_token_github_oauth_molto_segreto"
    }
}
```

Riassunto della struttura delle cartelle

```txt
mio-progetto-laravel/
├── app/
├── config/
├── ...
├── auth.json         <-- Il nuovo file (Nascosto al Git)
├── composer.json     <-- Modificato con "repositories"
└── .gitignore        <-- Modificato aggiungendo "auth.json"
```

4. Installazione

```sh
composer update utente/nome-pacchetto
# (Oppure composer install se stai partendo da zero).
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
]
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

Edit `routes/web.php` or `routes/api.php` as follow:

```php
use NewTimeGroup\IdpClient\Http\Middleware\IdpAuthMiddleware;
...
Route::middleware([IdpAuthMiddleware::class])->group(function () {
});
```
