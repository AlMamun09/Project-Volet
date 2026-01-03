using System.Text.Json;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Volet.Application.DTOs.Currency;
using Volet.Application.Interfaces;

namespace Volet.Infrastructure.Services
{
    public class CurrencyConverterService : ICurrencyConverterService
    {
        private readonly HttpClient _httpClient;
        private readonly ILogger<CurrencyConverterService> _logger;

        // Cache for fiat currency IDs (symbol -> id)
        private static Dictionary<string, int>? _fiatCurrencyIds;
        private static readonly SemaphoreSlim _cacheLock = new(1, 1);

        // Fiat currency symbols (ISO 4217)
        private static readonly HashSet<string> FiatSymbols = new(StringComparer.OrdinalIgnoreCase)
        {
            "USD", "EUR", "GBP", "JPY", "AUD", "CAD", "CHF", "CNY", "INR", "BDT",
            "SGD", "MYR", "AED", "SAR", "HKD", "NZD", "SEK", "NOK", "DKK", "ZAR",
            "BRL", "MXN", "RUB", "KRW", "THB", "IDR", "PHP", "VND", "PKR", "EGP",
            "TRY", "PLN", "CZK", "HUF", "ILS", "CLP", "COP", "PEN", "ARS", "NGN"
        };

        // Currency name mappings
        private static readonly Dictionary<string, string> CurrencyNames = new(StringComparer.OrdinalIgnoreCase)
        {
            // Fiat Currencies
            { "BDT", "Bangladeshi Taka \"৳\"" },
            { "USD", "United States Dollar \"$\"" },
            { "EUR", "Euro \"€\"" },
            { "GBP", "British Pound \"£\"" },
            { "JPY", "Japanese Yen \"¥\"" },
            { "INR", "Indian Rupee \"₹\"" },
            { "CAD", "Canadian Dollar \"C$\"" },
            { "AUD", "Australian Dollar \"A$\"" },
            { "CHF", "Swiss Franc \"CHF\"" },
            { "CNY", "Chinese Yuan \"¥\"" },
            { "SGD", "Singapore Dollar \"S$\"" },
            { "MYR", "Malaysian Ringgit \"RM\"" },
            { "AED", "UAE Dirham \"د.إ\"" },
            { "SAR", "Saudi Riyal \"﷼\"" },
            { "HKD", "Hong Kong Dollar \"HK$\"" },
            { "NZD", "New Zealand Dollar \"NZ$\"" },
            { "SEK", "Swedish Krona \"kr\"" },
            { "NOK", "Norwegian Krone \"kr\"" },
            { "DKK", "Danish Krone \"kr\"" },
            { "ZAR", "South African Rand \"R\"" },
            { "BRL", "Brazilian Real \"R$\"" },
            { "MXN", "Mexican Peso \"$\"" },
            { "RUB", "Russian Ruble \"₽\"" },
            { "KRW", "South Korean Won \"₩\"" },
            { "THB", "Thai Baht \"฿\"" },
            { "IDR", "Indonesian Rupiah \"Rp\"" },
            { "PHP", "Philippine Peso \"₱\"" },
            { "VND", "Vietnamese Dong \"₫\"" },
            { "PKR", "Pakistani Rupee \"₨\"" },
            { "EGP", "Egyptian Pound \"E£\"" },
            { "TRY", "Turkish Lira \"₺\"" },
            { "PLN", "Polish Zloty \"zł\"" },
            // Cryptocurrencies
            { "BTC", "Bitcoin \"₿\"" },
            { "ETH", "Ethereum \"Ξ\"" },
            { "USDT", "Tether \"₮\"" },
            { "BNB", "BNB \"BNB\"" },
            { "XRP", "XRP \"XRP\"" },
            { "ADA", "Cardano \"₳\"" },
            { "DOGE", "Dogecoin \"Ð\"" },
            { "SOL", "Solana \"SOL\"" },
            { "DOT", "Polkadot \"DOT\"" },
            { "MATIC", "Polygon \"MATIC\"" },
            { "LTC", "Litecoin \"Ł\"" },
            { "SHIB", "Shiba Inu \"SHIB\"" },
            { "TRX", "TRON \"TRX\"" },
            { "AVAX", "Avalanche \"AVAX\"" },
            { "LINK", "Chainlink \"LINK\"" }
        };

        public CurrencyConverterService(
            HttpClient httpClient,
            IConfiguration configuration,
            ILogger<CurrencyConverterService> logger)
        {
            _httpClient = httpClient;
            _logger = logger;

            var apiKey = configuration["CoinMarketCap:ApiKey"] 
                ?? throw new InvalidOperationException("CoinMarketCap API key not configured");
            var baseUrl = configuration["CoinMarketCap:BaseUrl"] 
                ?? throw new InvalidOperationException("CoinMarketCap BaseUrl not configured");

            // Configure HttpClient only once
            if (_httpClient.BaseAddress == null)
            {
                _httpClient.BaseAddress = new Uri(baseUrl);
                _httpClient.DefaultRequestHeaders.Add("X-CMC_PRO_API_KEY", apiKey);
                _httpClient.DefaultRequestHeaders.Add("Accept", "application/json");
            }
        }

        public async Task<CurrencyConvertResponseDto?> ConvertCurrencyAsync(CurrencyConvertRequestDto request)
        {
            try
            {
                var fromSymbol = request.FromCurrency.ToUpper();
                var toSymbol = request.ToCurrency.ToUpper();
                var isFiatFrom = FiatSymbols.Contains(fromSymbol);
                var isFiatTo = FiatSymbols.Contains(toSymbol);

                _logger.LogInformation("Converting {Amount} {From} to {To}", request.Amount, fromSymbol, toSymbol);

                // Ensure fiat IDs are loaded
                if (_fiatCurrencyIds == null)
                {
                    await LoadFiatCurrencyIdsAsync();
                }

                // Route to appropriate conversion method
                if (isFiatFrom && isFiatTo)
                {
                    return await ConvertFiatToFiatAsync(request.Amount, fromSymbol, toSymbol);
                }
                else if (!isFiatFrom && isFiatTo)
                {
                    return await ConvertCryptoToFiatAsync(request.Amount, fromSymbol, toSymbol);
                }
                else if (isFiatFrom && !isFiatTo)
                {
                    return await ConvertFiatToCryptoAsync(request.Amount, fromSymbol, toSymbol);
                }
                else
                {
                    return await ConvertCryptoToCryptoAsync(request.Amount, fromSymbol, toSymbol);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during currency conversion");
                return null;
            }
        }

        // Fiat to Fiat conversion using USDT as stable intermediary (e.g., BDT -> USD)
        private async Task<CurrencyConvertResponseDto?> ConvertFiatToFiatAsync(decimal amount, string fromSymbol, string toSymbol)
        {
            var fromFiatId = GetFiatId(fromSymbol);
            var toFiatId = GetFiatId(toSymbol);

            if (fromFiatId == 0 || toFiatId == 0)
            {
                _logger.LogWarning("Fiat currency ID not found for {From} or {To}", fromSymbol, toSymbol);
                return null;
            }

            var usdtInFrom = await GetUsdtPriceInFiat(fromFiatId);
            var usdtInTo = await GetUsdtPriceInFiat(toFiatId);

            if (usdtInFrom == null || usdtInTo == null)
            {
                return null;
            }

            var usdtAmount = amount / usdtInFrom.Value.Price;
            var convertedAmount = usdtAmount * usdtInTo.Value.Price;
            var exchangeRate = usdtInTo.Value.Price / usdtInFrom.Value.Price;

            return new CurrencyConvertResponseDto
            {
                OriginalAmount = amount,
                FromCurrency = fromSymbol,
                FromCurrencyName = GetCurrencyName(fromSymbol),
                ConvertedAmount = Math.Round(convertedAmount, 2),
                ToCurrency = toSymbol,
                ToCurrencyName = GetCurrencyName(toSymbol),
                ExchangeRate = Math.Round(exchangeRate, 6),
                LastUpdated = usdtInFrom.Value.LastUpdated
            };
        }

        // Crypto to Fiat conversion (e.g., BTC -> USD)
        private async Task<CurrencyConvertResponseDto?> ConvertCryptoToFiatAsync(decimal amount, string cryptoSymbol, string fiatSymbol)
        {
            var fiatId = GetFiatId(fiatSymbol);
            if (fiatId == 0)
            {
                _logger.LogWarning("Fiat currency ID not found for {Fiat}", fiatSymbol);
                return null;
            }

            var queryString = $"/v1/tools/price-conversion?amount={amount}&symbol={cryptoSymbol}&convert_id={fiatId}";
            var (success, content) = await MakeApiRequestAsync(queryString);

            if (!success || content == null) return null;

            using var document = JsonDocument.Parse(content);
            var root = document.RootElement;

            if (root.TryGetProperty("data", out var data) &&
                data.TryGetProperty("quote", out var quote) &&
                quote.TryGetProperty(fiatId.ToString(), out var fiatQuote))
            {
                var convertedAmount = fiatQuote.GetProperty("price").GetDecimal();
                var lastUpdated = fiatQuote.GetProperty("last_updated").GetDateTime();
                var exchangeRate = amount > 0 ? convertedAmount / amount : 0;

                return new CurrencyConvertResponseDto
                {
                    OriginalAmount = amount,
                    FromCurrency = cryptoSymbol,
                    FromCurrencyName = GetCurrencyName(cryptoSymbol),
                    ConvertedAmount = Math.Round(convertedAmount, 2),
                    ToCurrency = fiatSymbol,
                    ToCurrencyName = GetCurrencyName(fiatSymbol),
                    ExchangeRate = Math.Round(exchangeRate, 6),
                    LastUpdated = lastUpdated
                };
            }

            return null;
        }

        // Fiat to Crypto conversion (e.g., USD -> BTC)
        private async Task<CurrencyConvertResponseDto?> ConvertFiatToCryptoAsync(decimal amount, string fiatSymbol, string cryptoSymbol)
        {
            var fiatId = GetFiatId(fiatSymbol);
            if (fiatId == 0)
            {
                _logger.LogWarning("Fiat currency ID not found for {Fiat}", fiatSymbol);
                return null;
            }

            // Get price of 1 crypto in the fiat currency
            var queryString = $"/v1/tools/price-conversion?amount=1&symbol={cryptoSymbol}&convert_id={fiatId}";
            var (success, content) = await MakeApiRequestAsync(queryString);

            if (!success || content == null) return null;

            using var document = JsonDocument.Parse(content);
            var root = document.RootElement;

            if (root.TryGetProperty("data", out var data) &&
                data.TryGetProperty("quote", out var quote) &&
                quote.TryGetProperty(fiatId.ToString(), out var fiatQuote))
            {
                var cryptoPriceInFiat = fiatQuote.GetProperty("price").GetDecimal();
                var lastUpdated = fiatQuote.GetProperty("last_updated").GetDateTime();

                var convertedAmount = cryptoPriceInFiat > 0 ? amount / cryptoPriceInFiat : 0;
                var exchangeRate = cryptoPriceInFiat > 0 ? 1 / cryptoPriceInFiat : 0;

                return new CurrencyConvertResponseDto
                {
                    OriginalAmount = amount,
                    FromCurrency = fiatSymbol,
                    FromCurrencyName = GetCurrencyName(fiatSymbol),
                    ConvertedAmount = Math.Round(convertedAmount, 8),
                    ToCurrency = cryptoSymbol,
                    ToCurrencyName = GetCurrencyName(cryptoSymbol),
                    ExchangeRate = Math.Round(exchangeRate, 10),
                    LastUpdated = lastUpdated
                };
            }

            return null;
        }

        // Crypto to Crypto conversion (e.g., BTC -> ETH)
        private async Task<CurrencyConvertResponseDto?> ConvertCryptoToCryptoAsync(decimal amount, string fromCrypto, string toCrypto)
        {
            var queryString = $"/v1/tools/price-conversion?amount={amount}&symbol={fromCrypto}&convert={toCrypto}";
            var (success, content) = await MakeApiRequestAsync(queryString);

            if (!success || content == null) return null;

            using var document = JsonDocument.Parse(content);
            var root = document.RootElement;

            if (root.TryGetProperty("data", out var data) &&
                data.TryGetProperty("quote", out var quote) &&
                quote.TryGetProperty(toCrypto, out var targetQuote))
            {
                var convertedAmount = targetQuote.GetProperty("price").GetDecimal();
                var lastUpdated = targetQuote.GetProperty("last_updated").GetDateTime();
                var exchangeRate = amount > 0 ? convertedAmount / amount : 0;

                return new CurrencyConvertResponseDto
                {
                    OriginalAmount = amount,
                    FromCurrency = fromCrypto,
                    FromCurrencyName = GetCurrencyName(fromCrypto),
                    ConvertedAmount = Math.Round(convertedAmount, 8),
                    ToCurrency = toCrypto,
                    ToCurrencyName = GetCurrencyName(toCrypto),
                    ExchangeRate = Math.Round(exchangeRate, 8),
                    LastUpdated = lastUpdated
                };
            }

            return null;
        }

        // Get USDT price in a fiat currency (USDT ID: 825)
        private async Task<(decimal Price, DateTime LastUpdated)?> GetUsdtPriceInFiat(int fiatId)
        {
            var queryString = $"/v1/tools/price-conversion?amount=1&id=825&convert_id={fiatId}";
            var (success, content) = await MakeApiRequestAsync(queryString);

            if (!success || content == null) return null;

            using var document = JsonDocument.Parse(content);
            var root = document.RootElement;

            if (root.TryGetProperty("data", out var data) &&
                data.TryGetProperty("quote", out var quote) &&
                quote.TryGetProperty(fiatId.ToString(), out var fiatQuote))
            {
                var price = fiatQuote.GetProperty("price").GetDecimal();
                var lastUpdated = fiatQuote.GetProperty("last_updated").GetDateTime();
                return (price, lastUpdated);
            }

            return null;
        }

        // Makes API request and handles all HTTP status codes
        private async Task<(bool Success, string? Content)> MakeApiRequestAsync(string endpoint)
        {
            try
            {
                var response = await _httpClient.GetAsync(endpoint);
                var content = await response.Content.ReadAsStringAsync();

                switch ((int)response.StatusCode)
                {
                    case 200:
                        return (true, content);

                    case 400:
                        _logger.LogWarning("Bad Request (400): Invalid parameters - {Endpoint}", endpoint);
                        return (false, null);

                    case 401:
                        _logger.LogError("Unauthorized (401): Invalid API key");
                        return (false, null);

                    case 402:
                        _logger.LogError("Payment Required (402): API subscription expired or limit reached");
                        return (false, null);

                    case 403:
                        _logger.LogError("Forbidden (403): Access denied - check API key permissions");
                        return (false, null);

                    case 429:
                        _logger.LogWarning("Too Many Requests (429): Rate limit exceeded - please wait before retrying");
                        return (false, null);

                    case 500:
                        _logger.LogError("Internal Server Error (500): CoinMarketCap server error");
                        return (false, null);

                    default:
                        _logger.LogError("API error ({StatusCode}): {Content}", (int)response.StatusCode, content);
                        return (false, null);
                }
            }
            catch (HttpRequestException ex)
            {
                _logger.LogError(ex, "Network error calling CoinMarketCap API");
                return (false, null);
            }
            catch (TaskCanceledException ex)
            {
                _logger.LogError(ex, "Request timeout calling CoinMarketCap API");
                return (false, null);
            }
        }

        // Load fiat currency IDs from CoinMarketCap API
        private async Task LoadFiatCurrencyIdsAsync()
        {
            await _cacheLock.WaitAsync();
            try
            {
                if (_fiatCurrencyIds != null) return;

                _logger.LogInformation("Loading fiat currency IDs from CoinMarketCap");

                var (success, content) = await MakeApiRequestAsync("/v1/fiat/map");

                if (!success || content == null)
                {
                    _logger.LogWarning("Failed to load fiat map, using defaults");
                    _fiatCurrencyIds = GetDefaultFiatIds();
                    return;
                }

                using var document = JsonDocument.Parse(content);
                var root = document.RootElement;

                _fiatCurrencyIds = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

                if (root.TryGetProperty("data", out var data))
                {
                    foreach (var item in data.EnumerateArray())
                    {
                        var id = item.GetProperty("id").GetInt32();
                        var symbol = item.GetProperty("symbol").GetString();
                        if (!string.IsNullOrEmpty(symbol))
                        {
                            _fiatCurrencyIds[symbol] = id;
                        }
                    }
                }

                _logger.LogInformation("Loaded {Count} fiat currency IDs", _fiatCurrencyIds.Count);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error loading fiat map, using defaults");
                _fiatCurrencyIds = GetDefaultFiatIds();
            }
            finally
            {
                _cacheLock.Release();
            }
        }

        private int GetFiatId(string symbol)
        {
            if (_fiatCurrencyIds != null && _fiatCurrencyIds.TryGetValue(symbol, out var id))
            {
                return id;
            }
            var defaults = GetDefaultFiatIds();
            return defaults.TryGetValue(symbol, out var defaultId) ? defaultId : 0;
        }

        private static Dictionary<string, int> GetDefaultFiatIds()
        {
            return new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase)
            {
                { "USD", 2781 }, { "EUR", 2790 }, { "GBP", 2791 }, { "JPY", 2797 },
                { "AUD", 2782 }, { "CAD", 2784 }, { "CHF", 2785 }, { "CNY", 2787 },
                { "INR", 2796 }, { "BDT", 2789 }, { "SGD", 2808 }, { "MYR", 2800 },
                { "AED", 2813 }, { "SAR", 2807 }, { "HKD", 2792 }, { "NZD", 2802 },
                { "SEK", 2807 }, { "KRW", 2798 }, { "THB", 2809 }, { "IDR", 2794 },
                { "PHP", 2803 }, { "PKR", 2804 }, { "TRY", 2810 }, { "BRL", 2783 },
                { "MXN", 2799 }, { "ZAR", 2812 }, { "RUB", 2806 }, { "PLN", 2805 }
            };
        }

        private static string GetCurrencyName(string symbol)
        {
            return CurrencyNames.TryGetValue(symbol, out var name) ? name : symbol.ToUpper();
        }
    }
}
