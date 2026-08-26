<?php

function read_export(): string|false
{
    $path = $_GET["path"];
    return file_get_contents($path);
}
