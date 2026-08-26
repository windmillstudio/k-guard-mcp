def read_public_guide(params)
  document = params[:document]
  raise ArgumentError, "unknown document" unless %w[guide terms].include?(document)

  File.read("/srv/public/guide.txt")
end
