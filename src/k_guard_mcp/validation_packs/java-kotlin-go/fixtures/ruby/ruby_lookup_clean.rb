def lookup_owned_account(current_user, params)
  current_user.accounts.find(params[:account_id])
end
