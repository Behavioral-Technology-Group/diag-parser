Rails.application.routes.draw do
  post root, to: "parse#create"
end
