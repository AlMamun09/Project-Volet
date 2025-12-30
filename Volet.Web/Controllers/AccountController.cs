using Microsoft.AspNetCore.Mvc;

namespace Volet.Web.Controllers
{
    [Route("[controller]/[action]")]
    public class AccountController : Controller
    {
        // /Account/Login  AND  /login
        [HttpGet]
        [HttpGet("/login")]
        public IActionResult Login() => View();

        // /Account/Register  AND  /register
        [HttpGet]
        [HttpGet("/register")]
        public IActionResult Register() => View();

        // /Account/SetupAuthenticator  AND  /setup-authenticator
        [HttpGet]
        [HttpGet("/setup-authenticator")]
        public IActionResult SetupAuthenticator() => View();

        // /Account/TwoFactorSettings  AND  /security-settings
        [HttpGet]
        [HttpGet("/security-settings")]
        public IActionResult TwoFactorSettings() => View();
    }
}
