using System;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.AspNetCore.Connections;
using OpenSSL.PrivateKeyDecoder;
using VaultSharp;
using VaultSharp.V1.SecretsEngines.PKI;

namespace SecretGenerator.Services
{
    public class VaultSharpServerCertificateProvider : IServerCertificateProvider
    {
        private readonly object _lock = new object();

        private readonly VaultClient _client;
        private X509Certificate2 _certificate;

        public VaultSharpServerCertificateProvider(IVaultSharpService vaultSharpService)
        {
            _client = vaultSharpService.VaultClient;
        }

        public X509Certificate2 ServerCertificateSelector(ConnectionContext connectionContext, string host)
        {
            if(_certificate == null)
            {
                lock(_lock)
                {
                    if(_certificate == null)
                    {
                        _certificate = GetServerCertificateFromVault();
                    }
                }
            }

            return _certificate;
        }

        private X509Certificate2 GetServerCertificateFromVault()
        {
            var certificateCredentialRequestOptions = new CertificateCredentialsRequestOptions()
            {
                CertificateFormat = CertificateFormat.pem,
                CommonName = "localhost",
            };

            var certSecret = _client.V1.Secrets.PKI.GetCredentialsAsync("app-backends", certificateCredentialRequestOptions).GetAwaiter().GetResult();
            return CreateX509FromVaultCertificate(certSecret.Data);
        }

        private static X509Certificate2 CreateX509FromVaultCertificate(CertificateCredentials data)
        {
            var publicKeyBytes = Encoding.UTF8.GetBytes(data.CertificateContent);
            var publicKey = new X509Certificate2(publicKeyBytes, string.Empty, X509KeyStorageFlags.EphemeralKeySet);

            // https://github.com/StefH/OpenSSL-X509Certificate2-Provider
            var decoder = new OpenSSLPrivateKeyDecoder();
            var privateKey = decoder.Decode(data.PrivateKeyContent);
            var privateKeyParameters = decoder.DecodeParameters(data.PrivateKeyContent);

            // Combine the public key & private key using the CopyWithPrivateKey extension method
            // https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.rsacertificateextensions.copywithprivatekey?view=netcore-2.2
            using (var certwithkey = publicKey.CopyWithPrivateKey(privateKey))
            {
                return new X509Certificate2(certwithkey.Export(X509ContentType.Pkcs12));
            }
        }
    }
}
