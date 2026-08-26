<?php

function read_public_guide(): string|false
{
    $document = $_GET["document"];
    if (!in_array($document, ["guide", "terms"], true)) {
        throw new InvalidArgumentException("unknown document");
    }
    return file_get_contents("/srv/public/guide.txt");
}
