using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace SecretGenerator.Models
{
    public class LoginTotpViewModel
    {
        public string TotpCode { get; set; }
        public string ReturnUrl { get; set; }
    }
}
