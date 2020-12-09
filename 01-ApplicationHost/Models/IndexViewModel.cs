using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace SecretGenerator.Models
{
    public class IndexViewModel
    {
        public bool TotpEnabled { get; set; }

        public IEnumerable<string> VaultCapabilities { get; set; }
    }
}
