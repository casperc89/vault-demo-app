using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace SecretGenerator.Controllers
{
    [Authorize]
    [Route("credentials")]
    public class VaultCredentialsController : Controller
    {

        [HttpGet("rabbitmq", Name = "rabbitmq-creds")]
        public async Task<IActionResult> CreateRabbitMQCreds()
        {
            await Task.CompletedTask;
            return View();
        }

        [HttpPost("rabbitmq")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> CreateRabbitMQCreds([FromForm] string key, [FromForm] string totpCode)
        {
            var vaultClient = CreateVaultUserClient();

            var vaultCreds = await vaultClient.V1.Secrets.RabbitMQ.GetCredentialsAsync("app-user");

            var cred = new Models.RabbitMQCredential()
            {
                Username = vaultCreds.Data.Username,
                Password = vaultCreds.Data.Password,
                LeaseId = vaultCreds.LeaseId,
                LeaseDuration = TimeSpan.FromSeconds(vaultCreds.LeaseDurationSeconds),
            };

            return View(cred);
        }

        private VaultSharp.VaultClient CreateVaultUserClient()
        {
            var tokenClaim = User.FindFirst("Vault:ClientToken");
            var vaultSettings = new VaultSharp.VaultClientSettings("http://127.0.0.1:8200", new VaultSharp.V1.AuthMethods.Token.TokenAuthMethodInfo(tokenClaim.Value));
            var vaultClient = new VaultSharp.VaultClient(vaultSettings);

            return vaultClient;
        }
    }
}