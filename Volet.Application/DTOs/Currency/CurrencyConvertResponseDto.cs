namespace Volet.Application.DTOs.Currency
{
    /// <summary>
    /// Response model for currency conversion result
    /// </summary>
    public class CurrencyConvertResponseDto
    {
        /// <summary>
        /// Original amount before conversion
        /// </summary>
        /// <example>100.00</example>
        public decimal OriginalAmount { get; set; }

        /// <summary>
        /// Source currency symbol
        /// </summary>
        /// <example>USD</example>
        public string FromCurrency { get; set; } = string.Empty;

        /// <summary>
        /// Full name of source currency
        /// </summary>
        /// <example>United States Dollar</example>
        public string FromCurrencyName { get; set; } = string.Empty;

        /// <summary>
        /// Converted amount in target currency
        /// </summary>
        /// <example>12150.50</example>
        public decimal ConvertedAmount { get; set; }

        /// <summary>
        /// Target currency symbol
        /// </summary>
        /// <example>BDT</example>
        public string ToCurrency { get; set; } = string.Empty;

        /// <summary>
        /// Full name of target currency
        /// </summary>
        /// <example>Bangladeshi Taka</example>
        public string ToCurrencyName { get; set; } = string.Empty;

        /// <summary>
        /// Exchange rate used for conversion
        /// </summary>
        /// <example>121.505</example>
        public decimal ExchangeRate { get; set; }

        /// <summary>
        /// Timestamp when the exchange rate was last updated
        /// </summary>
        public DateTime LastUpdated { get; set; }
    }
}
