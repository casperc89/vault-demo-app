namespace SecretGenerator.Models
{
    public class TotpConfirmationViewModel
    {
        public string TotpBase64EncodeBarcode { get; set; }

        public string TotpCode { get; set; }
    }
}
