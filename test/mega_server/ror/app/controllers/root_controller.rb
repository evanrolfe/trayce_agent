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
end
