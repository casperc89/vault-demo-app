# Policy to generate new rabbitmq credentials
path "rabbitmq/creds/app-user" {
    capabilities = ["read"]
}