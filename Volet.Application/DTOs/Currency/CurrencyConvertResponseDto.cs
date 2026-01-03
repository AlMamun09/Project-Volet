namespace Volet.Application.DTOs.Currency
{
    public class CurrencyConvertResponseDto
    {
        public decimal OriginalAmount { get; set; }
        public string FromCurrency { get; set; } = string.Empty;
        public string FromCurrencyName { get; set; } = string.Empty;
        public decimal ConvertedAmount { get; set; }
        public string ToCurrency { get; set; } = string.Empty;
        public string ToCurrencyName { get; set; } = string.Empty;
        public decimal ExchangeRate { get; set; }
        public DateTime LastUpdated { get; set; }
    }
}
