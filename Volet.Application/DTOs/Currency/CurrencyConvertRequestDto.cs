namespace Volet.Application.DTOs.Currency
{
    /// <summary>
    /// Request model for currency conversion
    /// </summary>
    public class CurrencyConvertRequestDto
    {
        /// <summary>
        /// Amount to convert (must be greater than 0)
        /// </summary>
        /// <example>100.00</example>
        public decimal Amount { get; set; }

        /// <summary>
        /// Source currency symbol (e.g., USD, BTC, EUR)
        /// </summary>
        /// <example>USD</example>
        public string FromCurrency { get; set; } = string.Empty;

        /// <summary>
        /// Target currency symbol (e.g., BDT, ETH, GBP)
        /// </summary>
        /// <example>BDT</example>
        public string ToCurrency { get; set; } = string.Empty;
    }
}
