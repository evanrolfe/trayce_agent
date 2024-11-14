require 'net/http'
require 'uri'

class RootController < ApplicationController
  def index
    if params[:id].present?
        output = "hello world: #{params[:id]}"
    else
        output = "hello world"
    end
    # sleep 5
    render plain: output, layout: false, content_type: 'text/plain'
  end

  def second_http
    uri = URI.parse("http://trayce.dev")
    http = Net::HTTP.new(uri.host, uri.port)
    request = Net::HTTP::Get.new(uri.request_uri)
    response = http.request(request)
    puts "=======================> Response Code: #{response.code}"

    output = "hello world"
    render plain: output, layout: false, content_type: 'text/plain'
  end

  def second_https
    uri = URI.parse("https://trayce.dev")
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true
    request = Net::HTTP::Get.new(uri.request_uri)
    response = http.request(request)
    puts "=======================> Response Code: #{response.code}"

    output = "hello world"
    render plain: output, layout: false, content_type: 'text/plain'
  end

  def large
    output = (0..999).to_a.join(',')
    render plain: output, layout: false, content_type: 'text/plain'
  end
end
