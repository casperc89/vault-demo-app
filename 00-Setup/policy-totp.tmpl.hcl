# Policy to manage totp for the user
path "totp/keys/{{identity.entity.aliases._accessor_.name}}" {
    capabilities = ["create", "read", "update", "delete"]
}

# Policy to validate a totp code for the given user
path "totp/code/{{identity.entity.aliases._accessor_.name}}" {
    capabilities = ["create", "update", "read"]
}