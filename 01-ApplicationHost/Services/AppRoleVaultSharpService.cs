using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using SecretGenerator.AppSettings;
using VaultSharp;
using VaultSharp.V1.AuthMethods.AppRole;

namespace SecretGenerator.Services
{
    public class AppRoleVaultSharpService : IVaultSharpService
    {
        public AppRoleVaultSharpService(IOptions<VaultSettings> options)
        {
            var configuration = options.Value;

            var authMethod = new AppRoleAuthMethodInfo(configuration.AppRoleId, configuration.AppRoleSecret);
            var settings = new VaultClientSettings(configuration.VaultEndpointUri, authMethod);

            VaultClient = new VaultClient(settings);
        }

        public VaultClient VaultClient { get; }
    }
}
