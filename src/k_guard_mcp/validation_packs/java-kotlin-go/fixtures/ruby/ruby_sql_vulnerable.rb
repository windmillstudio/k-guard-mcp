def load_account(database, params)
  account_id = params[:account_id]
  database.execute("SELECT * FROM accounts WHERE id = '#{account_id}'")
end
