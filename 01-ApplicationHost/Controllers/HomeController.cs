using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using SecretGenerator.AppSettings;
using SecretGenerator.Models;

namespace SecretGenerator.Controllers
{
    [Authorize]
    public class HomeController : Controller
    {
        private readonly VaultSettings _settings;

        public HomeController(IOptions<VaultSettings> options)
        {
            _settings = options.Value;
        }

        public async Task<IActionResult> Index()
        {
            await Task.CompletedTask;

            var user = HttpContext.User;
            var backends = user.FindAll(VaultClaims.Capability).Select(x => x.Value);
            var model = new IndexViewModel()
            {
                TotpEnabled = _settings.TotpEnabled,
                VaultCapabilities = backends
            };

            return View(model);
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
