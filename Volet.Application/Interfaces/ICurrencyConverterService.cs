using Volet.Application.DTOs.Currency;

namespace Volet.Application.Interfaces
{
    public interface ICurrencyConverterService
    {
        Task<CurrencyConvertResponseDto?> ConvertCurrencyAsync(CurrencyConvertRequestDto request);
    }
}
