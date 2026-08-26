<?php

function run_fixed_report(): void
{
    $requestedFormat = $_POST["format"];
    $format = in_array($requestedFormat, ["json", "csv"], true) ? $requestedFormat : "json";
    proc_open(["/usr/bin/report", "--format", $format], [], $pipes);
}
