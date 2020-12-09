using Microsoft.Extensions.Configuration;
using SecretGenerator.AppSettings;
using SecretGenerator.Services;
using System.Collections.Generic;
using VaultSharp;

namespace Microsoft.Extensions.DependencyInjection
{
    public static class VaultServiceProviderExtensions
    {
        public static void AddVaultClient(this IServiceCollection services, IConfiguration configuration)
        {
            services.Configure<VaultSettings>(configuration);
            services.AddSingleton<IVaultSharpService, AppRoleVaultSharpService>();

            services.PostConfigure<VaultSettings>(x =>
            {
                if(!string.IsNullOrEmpty(x.BootstrapToken))
                {
                    var bootstrapClient = CreateBootstrappingVaultClient(x);
                    var secret = bootstrapClient.V1.System.UnwrapWrappedResponseDataAsync<Dictionary<string, string>>(null).GetAwaiter().GetResult();
                    var secretId = secret.Data["secret_id"];

                    x.AppRoleSecret = secretId;
                }
            });
        }

        private static VaultClient CreateBootstrappingVaultClient(VaultSettings configuration)
        {
            var authMethod = new VaultSharp.V1.AuthMethods.Token.TokenAuthMethodInfo(configuration.BootstrapToken);
            var settings = new VaultClientSettings(configuration.VaultEndpointUri, authMethod);

            return new VaultClient(settings);
        }
    }
}
