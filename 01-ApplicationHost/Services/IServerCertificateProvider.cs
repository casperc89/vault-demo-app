using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Connections;

namespace SecretGenerator.Services
{
    public interface IServerCertificateProvider
    {
        X509Certificate2 ServerCertificateSelector(ConnectionContext connectionContext, string host);
    }
}
