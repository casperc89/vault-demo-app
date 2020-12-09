# Vault CLI commands

Vault CLI setup
```powershell
$env:VAULT_TOKEN="myroot"
$env:VAULT_ADDR="http://127.0.0.1:8200"

```

## Demo 1 - RabbitMQ Dynamic Credentials

### 1. Setup RabbitMQ secret engine

* Docs: https://www.vaultproject.io/docs/secrets/rabbitmq/index.html
* API Docs: https://www.vaultproject.io/api-docs/secret/rabbitmq/


```powershell
# enable the secret backend
vault secrets enable rabbitmq

# configure the rabbitmq connection
vault write rabbitmq/config/connection `
    connection_uri="http://rabbitmq:15672" `
    username="guest" `
    password="guest"

# configure the credentials TTL
vault write rabbitmq/config/lease @rmq-lease.json

# configure the role (used for ACL)
vault write rabbitmq/roles/app-user @rmq-role-app-user.json

```

#### Validation

```powershell
# Validate lease configuration & RMQ role
vault read rabbitmq/config/lease
vault read rabbitmq/roles/app-user
vault read rabbitmq/creds/app-user

```

### 2. Setup Userpass auth method & ACL

* https://www.vaultproject.io/docs/auth/userpass/
* https://www.vaultproject.io/api/auth/userpass/index.html#createupdate-user

```powershell
# enable the userpass auth method
vault auth enable userpass

# create a policy for our app users
vault policy write app-users policy-app-users.hcl

# create user bob and map to the created policy
# 
vault write auth/userpass/users/bob `
    password=password `
    policies=app-users

```

#### Validation

```
# Validate policy & user
vault policy read app-users
vault read auth/userpass/users/bob

```

## Demo 2 - 2FA Authentication
### Setup TOTP secret backend & ACL

* https://www.vaultproject.io/docs/secrets/totp/index.html

```powershell
# Enable the secret backend
vault secrets enable totp

# Retrieve a mount accessor of the userpass auth
# We need this accessor to set specific ACL policies
$auths = vault auth list -format=json | ConvertFrom-Json
$accessor = $auths."userpass/".accessor

# Overwrite our placeholder with the actual mount accessor
(Get-Content policy-totp.tmpl.hcl) `
-replace '_accessor_',$accessor | Out-File policy-totp.hcl -Encoding ASCII

# create a policy for our users
vault policy write totp policy-totp.hcl

# map user bob to the policy
vault write auth/userpass/users/bob policies=app-users,totp

```

#### Validation

```
# Validate policy & user
vault policy read totp
vault read auth/userpass/users/bob

```

## Demo 3 - Dynamic TLS certificates

### 1. Setup PKI secret engine

* https://www.vaultproject.io/docs/secrets/pki/
* https://www.vaultproject.io/api/secret/pki/index.html#generate-certificate
* https://www.vaultproject.io/api/secret/pki/index.html#createupdate-role

```powershell
vault secrets enable pki

# Let HashiCorp Vault create a Root CA
# 8760h = 1y
vault secrets tune -max-lease-ttl=8760h pki

$ca = vault write pki/root/generate/internal `
    common_name=VaultCA `
    ttl=8760h -format=json | ConvertFrom-Json

# Output public key of the CA which can be used for trust
$ca.data.certificate > ca.crt

# Create a role that can be used to issue certificates
vault write pki/roles/app-backends `
    max_ttl=72h `
    allow_any_name=true

```

#### Validation

```
vault read pki/roles/app-backends

```


### 2. Setup  AppRole auth method & ACL

```powershell
# enable the auth backend
vault auth enable approle

# create a policy for app-backends
vault policy write app-backends policy-backend.hcl

# create a new approle named app-backend and map to the policy
vault write auth/approle/role/app-backend `
    policies=app-backends

# set a fixed a role id
vault write auth/approle/role/app-backend/role-id role_id=app-service

# Create an AppRole secret
vault write -f auth/approle/role/app-backend/secret-id

```

#### Validation

```
vault policy read app-backends
vault read auth/approle/role/app-backend

```

## Demo 4 - Application bootstrapping

### Create an AppRole Secret with Response Wrapping
```
# Create a response wrapped secret
vault write -f -wrap-ttl=5m auth/approle/role/app-backend/secret-id
```

Test response wrapping
```
$wrap = vault write -f -wrap-ttl=5m auth/approle/role/app-backend/secret-id -format=json | ConvertFrom-Json

vault unwrap $wrap.wrap_info.token
```
