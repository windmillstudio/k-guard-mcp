<?php

function lookup_account(): Account
{
    return Account::find($_GET["account_id"]);
}
