namespace Volet.Application.DTOs.Currency
{
    public class CurrencyConvertRequestDto
    {
        public decimal Amount { get; set; }
        public string FromCurrency { get; set; } = string.Empty;
        public string ToCurrency { get; set; } = string.Empty;
    }
}
