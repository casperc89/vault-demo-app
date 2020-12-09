using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using SecretGenerator.AppSettings;
using SecretGenerator.Models;
using VaultSharp;
using VaultSharp.Core;
using VaultSharp.V1.AuthMethods.Token;
using VaultSharp.V1.AuthMethods.UserPass;
using VaultSharp.V1.SecretsEngines.TOTP;

namespace SecretGenerator.Controllers
{
    public class AccountController : Controller
    {
        private readonly VaultSettings _vaultSettings;

        public AccountController(IOptions<VaultSettings> options)
        {
            _vaultSettings = options.Value;
        }

        [HttpGet]
        public IActionResult Login()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model)
        {
            // We're using the supplied user name and password to authenticate with Vault
            // and retrieve a user specific client token.
            var authMethodInfo = new UserPassAuthMethodInfo(model.Username, model.Password);
            var vaultClientSettings = new VaultClientSettings(_vaultSettings.VaultEndpointUri, authMethodInfo);
            var vaultClient = new VaultClient(vaultClientSettings);

            bool? hasRabbitMqCapability = await CheckRabbitMqCapabilityAsync(vaultClient);

            // Since this is was our first call to the Vault API,
            // we know that invalid credentials are provided when
            // token capabilties could not be retrieved.
            if (hasRabbitMqCapability == null)
            {
                ModelState.Clear();
                ModelState.AddModelError("", "Invalid username/password combination.");

                return View();
            }
            else
            {
                var claims = new List<string>
                {
                    $"{ClaimTypes.Name}::{model.Username}",

                    // Save the client token as a claim. It will get stored in the encrypted cookie.
                    $"{VaultClaims.ClientToken}::{authMethodInfo.ReturnedLoginAuthInfo.ClientToken}"
                };

                if (hasRabbitMqCapability == true)
                {
                    claims.Add($"{VaultClaims.Capability}::rabbitmq");
                }

                #region TOTP
                bool requiresTotp = _vaultSettings.TotpEnabled && await RequiresTotpAsync(model, vaultClient);
                if (requiresTotp)
                {
                    claims.Add($"{VaultClaims.Capability}::2fa");
                }

                if (requiresTotp)
                {
                    TempData[nameof(VaultClaims)] = claims;
                    return RedirectToAction("LoginTotp", new { model.ReturnUrl });
                }
                #endregion

                var claimsIdentity = new ClaimsIdentity(
                    claims.Select(x =>
                    {
                        var claim = x.Split("::");
                        return new Claim(claim[0], claim[1]);
                    }), CookieAuthenticationDefaults.AuthenticationScheme);

                var authProperties = new AuthenticationProperties();

                await HttpContext.SignInAsync(
                    CookieAuthenticationDefaults.AuthenticationScheme,
                    new ClaimsPrincipal(claimsIdentity),
                    authProperties);

                return LocalRedirect(model.ReturnUrl ?? "/");
            }
        }
        
        [HttpGet]
        public async Task<IActionResult> LoginTotp(string returnUrl)
        {
            if(!TempData.ContainsKey(nameof(VaultClaims)))
            {
                return RedirectToAction("Login", "Account", new { returnUrl });
            }

            await Task.CompletedTask;
            return View(new LoginTotpViewModel() { ReturnUrl = returnUrl });
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> LoginTotp(LoginTotpViewModel model)
        {
            if (!TempData.ContainsKey(nameof(VaultClaims)))
            {
                return RedirectToAction("Login", "Account", new { model.ReturnUrl });
            }

            // Retrieve the vault claims from TempData 
            // Data has been set by the Login method
            var vaultClaims = TempData.Peek(nameof(VaultClaims)) as string[];
            var claims = vaultClaims.Select(x => { var claim = x.Split("::"); return new Claim(claim[0], claim[1]); });

            // Use the ClientToken from the claimset to make authenticated Vault calls
            var authMethod = new TokenAuthMethodInfo(claims.First(x => x.Type == VaultClaims.ClientToken).Value);
            var vaultClientSettings = new VaultClientSettings(_vaultSettings.VaultEndpointUri, authMethod);
            var vaultClient = new VaultClient(vaultClientSettings);


            var nameClaim = claims.First(x => x.Type == ClaimTypes.Name).Value;
            bool isValidTotpCode = await ValidateTotpCodeAsync(vaultClient, nameClaim, model.TotpCode);

            if (isValidTotpCode)
            {
                var claimsIdentity = new ClaimsIdentity(
                   claims, CookieAuthenticationDefaults.AuthenticationScheme);

                var authProperties = new AuthenticationProperties();

                await HttpContext.SignInAsync(
                    CookieAuthenticationDefaults.AuthenticationScheme,
                    new ClaimsPrincipal(claimsIdentity),
                    authProperties);

                TempData.Remove(nameof(VaultClaims));
                return LocalRedirect(model.ReturnUrl ?? "/");
            }
            else
            {
                ModelState.Remove(nameof(model.TotpCode));
                ModelState.AddModelError(nameof(model.TotpCode), "Invalid code. Try again.");
                return View(new LoginTotpViewModel() { ReturnUrl = model.ReturnUrl });
            }
        }

        [HttpGet("account/details", Name = "account-details")]
        [Authorize]
        public async Task<IActionResult> AccountDetails()
        {
            await Task.CompletedTask;
            return View();
        }

        [HttpGet("account/disable-2fa", Name = "disable-2fa")]
        [Authorize]
        public async Task<IActionResult> DisableTwoFactorAuth()
        {
            await Task.CompletedTask;
            return View(new TotpConfirmationViewModel());
        }

        [HttpPost("account/disable-2fa")]
        [Authorize]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DisableTwoFactorAuth(TotpConfirmationViewModel model)
        {
            if (!User.HasClaim(c => c.Type == VaultClaims.Capability && c.Value == "2fa"))
            {
                return BadRequest();
            }

            var vaultClient = CreateVaultUserClient();
            bool isValidTotpCode = await ValidateTotpCodeAsync(vaultClient, User.Identity.Name, model.TotpCode);

            if (!isValidTotpCode)
            {
                ModelState.Remove(nameof(TotpConfirmationViewModel.TotpCode));
                ModelState.AddModelError(nameof(TotpConfirmationViewModel.TotpCode), "Invalid code. Try again.");
                return View(new TotpConfirmationViewModel());
            }
            else
            {
                await vaultClient.V1.Secrets.TOTP.DeleteKeyAsync(User.Identity.Name);

                // create a new identity from the old one
                // remove the 2fa capability
                // & refresh authentication cookie with the new claim set
                var identity = new ClaimsIdentity(User.Identity);
                var claim = identity.Claims.Where(x => x.Type == VaultClaims.Capability && x.Value == "2fa").First();
                identity.RemoveClaim(claim);

                var authProperties = new AuthenticationProperties();
                await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                await HttpContext.SignInAsync(
                    CookieAuthenticationDefaults.AuthenticationScheme,
                    new ClaimsPrincipal(identity),
                    authProperties);

                return RedirectToRoute("account-details");
            }
        }

        [HttpPost("account/enable-2fa", Name = "enable-2fa")]
        [Authorize]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> EnableTwoFactorAuth()
        {
            if (User.HasClaim(c => c.Type == VaultClaims.Capability && c.Value == "2fa"))
            {
                return BadRequest();
            }

            if (User.HasClaim(c => c.Type == VaultClaims.Capability && c.Value == "2fa-unconfirmed"))
            {
                return RedirectToRoute("confirm-2fa");
            }

            var vaultClient = CreateVaultUserClient();
            var req = new TOTPCreateKeyRequest()
            {
                Issuer = _vaultSettings.TotpIssuer,
                AccountName = $"{User.Identity.Name}@{_vaultSettings.TotpIssuer}"
            };
            var totpSecret = await vaultClient.V1.Secrets.TOTP.CreateKeyAsync(User.Identity.Name, req);

            TempData["TotpBarCode"] = totpSecret.Data.Barcode;

            // create a new identity from the old one
            // & refresh authentication cookie with the new claim set
            var identity = new ClaimsIdentity(User.Identity);
            identity.AddClaim(new Claim(VaultClaims.Capability, "2fa-unconfirmed"));

            var authProperties = new AuthenticationProperties();
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            await HttpContext.SignInAsync(
                CookieAuthenticationDefaults.AuthenticationScheme,
                new ClaimsPrincipal(identity),
                authProperties);

            return RedirectToRoute("confirm-2fa");
        }

        [HttpGet("account/confirm-2fa", Name = "confirm-2fa")]
        [Authorize]
        public async Task<IActionResult> ConfirmTwoFactorAuth()
        {
            if (!User.HasClaim(c => c.Type == VaultClaims.Capability && c.Value == "2fa-unconfirmed"))
            {
                return BadRequest();
            }

            await Task.CompletedTask;

            var barcode = TempData.Peek("TotpBarCode") as string;
            return View(new TotpConfirmationViewModel() { TotpBase64EncodeBarcode = barcode });
        }

        [HttpPost("account/confirm-2fa")]
        [Authorize]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ConfirmTwoFactorAuth(TotpConfirmationViewModel model)
        {
            if (!User.HasClaim(c => c.Type == VaultClaims.Capability && c.Value == "2fa-unconfirmed"))
            {
                return BadRequest();
            }

            var vaultClient = CreateVaultUserClient();
            var validateTotCodeSecret = await vaultClient.V1.Secrets.TOTP.ValidateCodeAsync(User.Identity.Name, model.TotpCode);
            bool isValidTotpCode = validateTotCodeSecret.Data.Valid;

            if (!isValidTotpCode)
            {
                ModelState.AddModelError(nameof(model.TotpCode), "Code is invalid. Please try again.");

                var barcode = TempData.Peek("TotpBarCode") as string;
                return View(new TotpConfirmationViewModel() { TotpBase64EncodeBarcode = barcode });
            }
            else
            {
                TempData.Remove("TotpBarCode");
                // create a new identity from the old one
                // & refresh authentication cookie with the new claim set
                var identity = new ClaimsIdentity(User.Identity);

                // Replace the 2fa-unconfirmed claim with a 2fa-confirmed claim
                var unconfirmed2faClaim = identity.FindFirst(x => x.Type == VaultClaims.Capability && x.Value == "2fa-unconfirmed");
                identity.RemoveClaim(unconfirmed2faClaim);

                identity.AddClaim(new Claim(VaultClaims.Capability, "2fa"));

                var authProperties = new AuthenticationProperties();
                await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                await HttpContext.SignInAsync(
                    CookieAuthenticationDefaults.AuthenticationScheme,
                    new ClaimsPrincipal(identity),
                    authProperties);

                return RedirectToRoute("account-details");
            }
        }

        private static async Task<bool?> CheckRabbitMqCapabilityAsync(VaultClient vaultClient)
        {
            try
            {
                // Check if we have permissions to read the rabbitmq creds
                // https://www.vaultproject.io/api-docs/system/capabilities-self/
                var rabbitMqCapability = await vaultClient.V1.System.GetCallingTokenCapabilitiesAsync("rabbitmq/creds/app-user");
                return rabbitMqCapability.Data.Capabilities.Contains("read");
            }
            catch (VaultApiException)
            {
            }

            return new bool?();
        }

        private static async Task<bool> ValidateTotpCodeAsync(VaultClient vaultClient, string keyName, string code)
        {
            try
            {
                var validateTotCodeSecret = await vaultClient.V1.Secrets.TOTP.ValidateCodeAsync(keyName, code);
                return validateTotCodeSecret.Data.Valid;
            }
            catch (VaultApiException)
            {
                return false;
            }
        }

        private static async Task<bool> RequiresTotpAsync(LoginViewModel model, VaultClient vaultClient)
        {
            try
            {
                var totpKey = await vaultClient.V1.Secrets.TOTP.GetCodeAsync(model.Username);
                return totpKey.Data != null;
            }
            catch (VaultApiException ex)
            when (ex.HttpStatusCode == System.Net.HttpStatusCode.BadRequest || ex.HttpStatusCode == System.Net.HttpStatusCode.NotFound || ex.HttpStatusCode == System.Net.HttpStatusCode.Forbidden)
            {
                return false;
            }
        }

        private VaultClient CreateVaultUserClient()
        {
            var tokenClaim = User.FindFirst(VaultClaims.ClientToken);
            var settings = new VaultClientSettings(_vaultSettings.VaultEndpointUri, new TokenAuthMethodInfo(tokenClaim.Value));
            var vaultClient = new VaultClient(settings);

            return vaultClient;
        }
    }
}