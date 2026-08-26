require "open3"

def run_fixed_report(params)
  requested_format = params[:format]
  format = %w[json csv].include?(requested_format) ? requested_format : "json"
  Open3.capture3("/usr/bin/report", "--format", format)
end
