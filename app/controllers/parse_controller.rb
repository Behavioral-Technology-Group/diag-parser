class ParseController < ApplicationController
 def create
  result = `python3 parselog.py --json #{params[:id].to_i}`
  
  if result[0..4] == "Error"
    render json: { error: "Can't parse file", log: [{name: "Error - can't parse file", v: {error: result}}] }
  else
    render json: result
  end
 end
 
 def ping
   render json: {ok: true}
 end
end