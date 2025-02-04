Rails.application.routes.draw do
  resources :things
  get "/", to: "root#index"
#   get "/:id", to: "root#index"
  get "/second_http", to: "root#second_http"
  get "/second_https", to: "root#second_https"
  get "/large", to: "root#large"

  # Define your application routes per the DSL in https://guides.rubyonrails.org/routing.html

  # Reveal health status on /up that returns 200 if the app boots with no exceptions, otherwise 500.
  # Can be used by load balancers and uptime monitors to verify that the app is live.
  get "up" => "rails/health#show", as: :rails_health_check

  # Defines the root path route ("/")
  # root "posts#index"
end
