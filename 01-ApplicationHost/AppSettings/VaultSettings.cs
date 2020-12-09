using System;

namespace SecretGenerator.AppSettings
{
    public class VaultSettings
    {
        public string VaultEndpointUri { get; set; }

        public string AppRoleId { get; set; }

        public string AppRoleSecret { get; set; }

        public string BootstrapToken { get; set; }

        public bool TotpEnabled { get; set; }

        public string TotpIssuer { get; set; }

    }
}
