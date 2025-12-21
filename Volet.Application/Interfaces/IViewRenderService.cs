namespace Volet.Application.Interfaces
{
    public interface IViewRenderService
    {
        Task<string> RenderToStringAsync(string viewName, object model);
    }
}
