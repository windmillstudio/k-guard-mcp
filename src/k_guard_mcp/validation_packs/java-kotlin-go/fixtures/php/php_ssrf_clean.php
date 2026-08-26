<?php

function fetch_health(): CurlHandle|false
{
    $requestedService = $_GET["service"];
    if ($requestedService !== "health") {
        throw new InvalidArgumentException("unknown service");
    }
    return curl_init("https://api.example.com/health");
}
