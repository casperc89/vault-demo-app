using System.Net;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.Extensions.DependencyInjection;
using SecretGenerator.Services;

namespace Microsoft.AspNetCore.Hosting
{
    public static class WebHostBuilderTlsSetupExtensions
    {
        public static IWebHostBuilder ConfigureDynamicTlsWithVault(this IWebHostBuilder builder)
        {
            builder.ConfigureServices(services =>
            {
                services.AddSingleton<IServerCertificateProvider, VaultSharpServerCertificateProvider>();
            });

            return builder.ConfigureKestrel(options =>
             {
                 options.Listen(IPAddress.Any, 443, listenOptions =>
                 {
                     listenOptions.UseHttps(new HttpsConnectionAdapterOptions()
                     {
                         SslProtocols = System.Security.Authentication.SslProtocols.Tls12,
                         
                         ServerCertificateSelector = options.ApplicationServices.GetService<IServerCertificateProvider>().ServerCertificateSelector,
                     });
                 });
             });
        }
    }
}
