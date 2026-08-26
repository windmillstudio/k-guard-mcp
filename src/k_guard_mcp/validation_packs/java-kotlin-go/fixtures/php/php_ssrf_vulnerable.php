<?php

function proxy_url(): CurlHandle|false
{
    $target = $_GET["url"];
    return curl_init($target);
}
