class ParseController < ApplicationController
 def create
  result = `python3 parselog --json #{params[:id].to_i}`
  render json: result
 end
end