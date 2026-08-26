<?php

function load_account_safely(PDO $database): array|false
{
    $accountId = $_GET["account_id"];
    $statement = $database->prepare("SELECT * FROM accounts WHERE id = ?");
    $statement->execute([$accountId]);
    return $statement->fetch();
}
