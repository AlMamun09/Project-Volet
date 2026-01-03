using Microsoft.AspNetCore.Mvc;
using Volet.Application.DTOs.Currency;
using Volet.Application.Interfaces;

namespace Volet.Web.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class CurrencyController : Controller
    {
        private readonly ICurrencyConverterService _currencyConverterService;
        private readonly ILogger<CurrencyController> _logger;

        public CurrencyController(
            ICurrencyConverterService currencyConverterService,
            ILogger<CurrencyController> logger)
        {
            _currencyConverterService = currencyConverterService;
            _logger = logger;
        }

        // Serves the currency converter page
        [HttpGet("/converter")]
        public IActionResult Converter()
        {
            return View();
        }

        // Convert currency using CoinMarketCap API
        [HttpPost("convert")]
        public async Task<IActionResult> Convert([FromBody] CurrencyConvertRequestDto request)
        {
            if (request.Amount <= 0)
            {
                return BadRequest(new { error = "Amount must be greater than 0" });
            }

            if (string.IsNullOrWhiteSpace(request.FromCurrency) || string.IsNullOrWhiteSpace(request.ToCurrency))
            {
                return BadRequest(new { error = "From and To currencies are required" });
            }

            _logger.LogInformation("Converting {Amount} {From} to {To}", 
                request.Amount, request.FromCurrency, request.ToCurrency);

            var result = await _currencyConverterService.ConvertCurrencyAsync(request);

            if (result == null)
            {
                return StatusCode(500, new { error = "Failed to convert currency. Please try again later." });
            }

            return Ok(result);
        }

        // Get list of supported currencies
        [HttpGet("currencies")]
        public IActionResult GetCurrencies()
        {
            var currencies = new[]
            {
                // Fiat Currencies
                new { symbol = "BDT", name = "Bangladeshi Taka \"৳\" (BDT)", type = "fiat" },
                new { symbol = "USD", name = "United States Dollar \"$\" (USD)", type = "fiat" },
                new { symbol = "EUR", name = "Euro \"€\" (EUR)", type = "fiat" },
                new { symbol = "GBP", name = "British Pound \"£\" (GBP)", type = "fiat" },
                new { symbol = "JPY", name = "Japanese Yen \"¥\" (JPY)", type = "fiat" },
                new { symbol = "INR", name = "Indian Rupee \"₹\" (INR)", type = "fiat" },
                new { symbol = "CAD", name = "Canadian Dollar \"C$\" (CAD)", type = "fiat" },
                new { symbol = "AUD", name = "Australian Dollar \"A$\" (AUD)", type = "fiat" },
                new { symbol = "CHF", name = "Swiss Franc \"CHF\" (CHF)", type = "fiat" },
                new { symbol = "CNY", name = "Chinese Yuan \"¥\" (CNY)", type = "fiat" },
                new { symbol = "SGD", name = "Singapore Dollar \"S$\" (SGD)", type = "fiat" },
                new { symbol = "MYR", name = "Malaysian Ringgit \"RM\" (MYR)", type = "fiat" },
                new { symbol = "AED", name = "UAE Dirham \"د.إ\" (AED)", type = "fiat" },
                new { symbol = "SAR", name = "Saudi Riyal \"﷼\" (SAR)", type = "fiat" },
                // Cryptocurrencies
                new { symbol = "BTC", name = "Bitcoin \"₿\" (BTC)", type = "crypto" },
                new { symbol = "ETH", name = "Ethereum \"Ξ\" (ETH)", type = "crypto" },
                new { symbol = "USDT", name = "Tether \"₮\" (USDT)", type = "crypto" },
                new { symbol = "BNB", name = "BNB \"BNB\" (BNB)", type = "crypto" },
                new { symbol = "XRP", name = "XRP \"XRP\" (XRP)", type = "crypto" },
                new { symbol = "ADA", name = "Cardano \"₳\" (ADA)", type = "crypto" },
                new { symbol = "DOGE", name = "Dogecoin \"Ð\" (DOGE)", type = "crypto" },
                new { symbol = "SOL", name = "Solana \"SOL\" (SOL)", type = "crypto" },
                new { symbol = "DOT", name = "Polkadot \"DOT\" (DOT)", type = "crypto" },
                new { symbol = "MATIC", name = "Polygon \"MATIC\" (MATIC)", type = "crypto" },
                new { symbol = "LTC", name = "Litecoin \"Ł\" (LTC)", type = "crypto" },
                new { symbol = "SHIB", name = "Shiba Inu \"SHIB\" (SHIB)", type = "crypto" },
                new { symbol = "TRX", name = "TRON \"TRX\" (TRX)", type = "crypto" },
                new { symbol = "AVAX", name = "Avalanche \"AVAX\" (AVAX)", type = "crypto" },
                new { symbol = "LINK", name = "Chainlink \"LINK\" (LINK)", type = "crypto" }
            };

            return Ok(currencies);
        }
    }
}
