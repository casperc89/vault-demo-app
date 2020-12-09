# Policy to manage totp for the user
path "totp/keys/{{identity.entity.aliases.auth_userpass_0cad0c87.name}}" {
    capabilities = ["create", "read", "update", "delete"]
}

# Policy to validate a totp code for the given user
path "totp/code/{{identity.entity.aliases.auth_userpass_0cad0c87.name}}" {
    capabilities = ["create", "update", "read"]
}
