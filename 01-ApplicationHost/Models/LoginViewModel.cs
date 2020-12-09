using System.ComponentModel.DataAnnotations;

namespace SecretGenerator.Models
{
    public class LoginViewModel
    {
        [Required]
        public string Username { get; set; }

        [Required]
        [DataType(DataType.Password)]
        public string Password { get; set; }

        [Required]
        [DataType(DataType.Password)]
        public string SecretPhrase { get; set; }


        public string ReturnUrl { get; set; }
    }
}
