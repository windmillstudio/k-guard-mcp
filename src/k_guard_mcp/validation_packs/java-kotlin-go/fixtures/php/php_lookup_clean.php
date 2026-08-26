<?php

function lookup_owned_account(int $authenticatedUserId): Account
{
    return Account::where("owner_id", $authenticatedUserId)
        ->findOrFail($_GET["account_id"]);
}
