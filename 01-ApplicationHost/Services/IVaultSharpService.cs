using VaultSharp;

namespace SecretGenerator.Services
{
    public interface IVaultSharpService
    {
        VaultClient VaultClient { get; }
    }
}
