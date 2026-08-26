require "faraday"

def fetch_health(params)
  service = params[:service]
  raise ArgumentError, "unknown service" unless service == "health"

  Faraday.get("https://api.example.com/health")
end
