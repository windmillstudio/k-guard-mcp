require "faraday"

def proxy_url(params)
  target = params[:url]
  Faraday.get(target)
end
