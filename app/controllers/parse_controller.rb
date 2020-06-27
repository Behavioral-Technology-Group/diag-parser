class ParseController < ApplicationController
 def create
  result = `python3 parselog.py --json #{params[:id].to_i}`
  render json: result
 end
 
 def ping
   render json: {ok: true}
 end
end