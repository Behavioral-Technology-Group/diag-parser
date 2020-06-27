Rails.application.routes.draw do
  get "/ping",  to: "parse#ping"
  post "/", to: "parse#create"
end
