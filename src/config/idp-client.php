<?php

return [
    "url" => env("IDP_URL"), // Base URL of your IDP (e.g. https://idp.example.com)
    "login_url" => env("IDP_URL_LOGIN"), // URL Query endpoint for login (e.g. https://idp.example.com/login)
    "client_id" => env("IDP_CLIENT_ID"), // ID of the client registered on the IDP
    "client_secret" => env("IDP_CLIENT_SECRET"), // Secret key for validating tokens (must match the one configured on the IDP)
];
