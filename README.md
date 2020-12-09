# Vault Demo Application
Source code used in demo's for DotnetFlix [episode 88](https://www.dotnetflix.com/player/88) & [episode 89](https://www.dotnetflix.com/player/89). In these episodes I showcase how [HashiCorp Vault](https://www.vaultproject.io/) can be implemented in your .NET applications to manage all kind of secrets.


Multiple topics's are being discussed:
* Dynamic credentials for RabbitMQ using the [RabbitMQ Secrets Engine](https://www.vaultproject.io/docs/secrets/rabbitmq)
* Authentication for application users with [Userpass Auth Method](https://www.vaultproject.io/docs/auth/userpass)
* Integrate 2FA with the [TOTP Secrets Engine](https://www.vaultproject.io/docs/secrets/totp)
* Short-lived TLS-certificates with the [PKI Secrets Engine](https://www.vaultproject.io/docs/secrets/pki)
* Application authentication & bootstrapping using the [AppRole Auth Method](https://www.vaultproject.io/docs/auth/approle) & [Response Wrapping](https://www.vaultproject.io/docs/concepts/response-wrapping)

Commands, configuration & docker-compose files used in the demo can be found in `./00-Setup` folder.

## Application arguments & settings
Variables can be found in `./01-ApplicationHost/Properties/launchSettings.json`

**Command line arguments**
1. `--Tls` - configures dynamic TLS endpoint, leave out to run without TLS

**Environment variables**
1. `VaultSettings__BootstrapToken` - used for application bootstrapping. May leave empty.
2. `VaultSettings__TotpEnabled` - `true/false` to enable/disable 2FA functions
3. `VaultSettings__AppRoleId` - App role of the application
4. `VaultSettings__AppRoleSecret` - fill when not using application bootstrapping


