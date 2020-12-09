namespace SecretGenerator.Models
{
    public class EnableTwoFactorAuthViewModel
    {
        public string TotpUri { get; set; }

        public string TotpBase64EncodeBarcode { get; set; }
    }
}
