<?php

function load_account(PDO $database): array|false
{
    $accountId = $_GET["account_id"];
    $statement = $database->query("SELECT * FROM accounts WHERE id = '" . $accountId . "'");
    return $statement->fetch();
}
