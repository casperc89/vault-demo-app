using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace SecretGenerator.Models
{
    public class RabbitMQCredential
    {
        public string Username { get; set; }

        public string Password { get; set; }

        public string LeaseId { get; set; }

        public TimeSpan LeaseDuration { get; set; }

    }
}
