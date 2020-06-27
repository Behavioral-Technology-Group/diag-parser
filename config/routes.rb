Rails.application.routes.draw do
  post "/", to: "parse#create"
end
