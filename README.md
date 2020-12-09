# Vault Demo Application
Source code used in demo's for DotnetFlix [episode 88](https://www.dotnetflix.com/player/88) & [episode 89](https://www.dotnetflix.com/player/89). In these episodes I showcase how [HashiCorp Vault](https://www.vaultproject.io/) can be implemented in your .NET applications to manage all kind of secrets.


Multiple topics's are being discussed:
* Dynamic credentials for RabbitMQ using the [RabbitMQ Secrets Engine](https://www.vaultproject.io/docs/secrets/rabbitmq)
* Authentication for application users with [Userpass Auth Method](https://www.vaultproject.io/docs/auth/userpass)
* Integrate 2FA with the [TOTP Secrets Engine](https://www.vaultproject.io/docs/secrets/totp)
* Short-lived TLS-certificates with the [PKI Secrets Engine](https://www.vaultproject.io/docs/secrets/pki)
* Application authentication & bootstrapping using the [AppRole Auth Method](https://www.vaultproject.io/docs/auth/approle) & [Response Wrapping](https://www.vaultproject.io/docs/concepts/response-wrapping)

Commands, configuration & docker-compose files used in the demo can be found in `Setup` folder.
