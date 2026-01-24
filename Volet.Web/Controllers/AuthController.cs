using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Volet.Application.DTOs;
using Volet.Application.DTOs.TwoFactor;
using Volet.Application.Interfaces;
using Volet.Domain.Entities;

namespace Volet.Web.Controllers
{
    /// <summary>
    /// Authentication controller for user registration, login, and two-factor authentication
    /// </summary>
    [Route("api/[controller]")]
    [ApiController]
    [Produces("application/json")]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IConfiguration _configuration;
        private readonly IEmailService _emailService;
        private readonly IViewRenderService _viewRenderService;
        private readonly ITotpService _totpService;

        public AuthController(
            UserManager<ApplicationUser> userManager, 
            IConfiguration configuration, 
            IEmailService emailService,
            IViewRenderService viewRenderService,
            ITotpService totpService)
        {
            _userManager = userManager;
            _configuration = configuration;
            _emailService = emailService;
            _viewRenderService = viewRenderService;
            _totpService = totpService;
        }

        /// <summary>
        /// Register a new user account
        /// </summary>
        /// <param name="model">Registration details including email, password, and consent flags</param>
        /// <returns>Success message with email confirmation instructions</returns>
        /// <response code="200">User created successfully, confirmation email sent</response>
        /// <response code="400">Validation error - missing required consents</response>
        /// <response code="500">User already exists or creation failed</response>
        [HttpPost("register")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public async Task<IActionResult> Register([FromBody] RegisterDto model)
        {
            // Check if user already exists
            var userExists = await _userManager.FindByEmailAsync(model.Email);
            if (userExists != null)
                return StatusCode(StatusCodes.Status500InternalServerError, new { Status = "Error", Message = "User already exists!" });

            // Validate required consents
            if (!model.HasAcceptedUserAgreement)
                return BadRequest(new { Status = "Error", Message = "You must accept the User Agreement to register." });

            if (!model.HasAcceptedPrivacyPolicy)
                return BadRequest(new { Status = "Error", Message = "You must accept the Privacy Policy to register." });

            // Create the user entity
            ApplicationUser user = new()
            {
                Email = model.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = model.Email,
                FirstName = model.FirstName,
                LastName = model.LastName,
                HasAcceptedUserAgreement = model.HasAcceptedUserAgreement,
                HasAcceptedPrivacyPolicy = model.HasAcceptedPrivacyPolicy,
                HasAcceptedNewsletterAndAnalytics = model.HasAcceptedNewsletterAndAnalytics,
                // 2FA disabled by default - users can enable it from security settings
                IsTwoFactorEnabled = false,
                TwoFactorMethod = null
            };

            // Save to DB (Identity handles password hashing automatically)
            var result = await _userManager.CreateAsync(user, model.Password);

            if (!result.Succeeded)
                return StatusCode(StatusCodes.Status500InternalServerError, new { Status = "Error", Message = "User creation failed! Please check user details and ensure password is strong." });

            // Generate JWT Token for Email Confirmation
            var confirmationToken = GenerateEmailConfirmationToken(user.Id, user.Email);

            // Build the Confirmation Link
            var confirmationLink = Url.Action(nameof(ConfirmEmail), "Auth", new { token = confirmationToken }, Request.Scheme);

            // Render email template
            var emailBody = await _viewRenderService.RenderToStringAsync("Emails/EmailConfirmation", confirmationLink);
            
            await _emailService.SendEmailAsync(user.Email, "Confirm your email", emailBody);

            return Ok(new { Status = "Success", Message = "User created successfully! Please check your email to confirm your account." });
        }

        /// <summary>
        /// Confirm email address using the token from confirmation email
        /// </summary>
        /// <param name="token">JWT token from confirmation email link</param>
        /// <returns>Redirects to login page with status</returns>
        [HttpGet("confirm-email")]
        [ProducesResponseType(StatusCodes.Status302Found)]
        public async Task<IActionResult> ConfirmEmail(string token)
        {
            try
            {
                // Validate and decode JWT token
                var tokenHandler = new JwtSecurityTokenHandler();
                var key = Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]!);
                
                var validationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = true,
                    ValidIssuer = _configuration["Jwt:Issuer"],
                    ValidateAudience = true,
                    ValidAudience = _configuration["Jwt:Audience"],
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.Zero
                };

                var principal = tokenHandler.ValidateToken(token, validationParameters, out SecurityToken validatedToken);
                
                // Extract user ID and email from token claims
                var userId = principal.FindFirst("UserId")?.Value;
                var email = principal.FindFirst(ClaimTypes.Email)?.Value;

                if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(email))
                    return Redirect("/login?error=invalid_token");

                var user = await _userManager.FindByIdAsync(userId);
                if (user == null || user.Email != email)
                    return Redirect("/login?error=user_not_found");

                if (user.EmailConfirmed)
                    return Redirect("/login?emailConfirmed=already");

                // Confirm the email
                user.EmailConfirmed = true;
                var result = await _userManager.UpdateAsync(user);

                if (result.Succeeded)
                {
                    return Redirect("/login?emailConfirmed=success");
                }

                return Redirect("/login?error=confirmation_failed");
            }
            catch (SecurityTokenExpiredException)
            {
                return Redirect("/login?error=token_expired");
            }
            catch (Exception)
            {
                return Redirect("/login?error=invalid_token");
            }
        }

        /// <summary>
        /// Resend the confirmation email to the user
        /// </summary>
        /// <param name="email">User's email address</param>
        /// <returns>Success message</returns>
        [HttpPost("resend-confirmation-email")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public async Task<IActionResult> ResendConfirmationEmail([FromBody] string email)
        {
            if (string.IsNullOrEmpty(email))
                return BadRequest(new { Status = "Error", Message = "Email is required." });

            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
                return NotFound(new { Status = "Error", Message = "User not found." });

            if (user.EmailConfirmed)
                return BadRequest(new { Status = "Error", Message = "Email is already confirmed." });

            // Generate JWT Token for Email Confirmation
            var confirmationToken = GenerateEmailConfirmationToken(user.Id, user.Email!);

            // Build the Confirmation Link
            var confirmationLink = Url.Action(nameof(ConfirmEmail), "Auth", new { token = confirmationToken }, Request.Scheme);

            // Render email template
            var emailBody = await _viewRenderService.RenderToStringAsync("Emails/EmailConfirmation", confirmationLink);

            await _emailService.SendEmailAsync(user.Email!, "Confirm your email", emailBody);

            return Ok(new { Status = "Success", Message = "Confirmation email sent successfully." });
        }

        /// <summary>
        /// Initiate login with credentials (step 1 of authentication)
        /// </summary>
        /// <remarks>
        /// If 2FA is enabled, returns challenge token and 2FA method.
        /// If 2FA is disabled, issues JWT token directly via cookie.
        /// </remarks>
        /// <param name="model">Login credentials (email, password, rememberMe)</param>
        /// <returns>Authentication result with optional 2FA challenge</returns>
        /// <response code="200">Login successful or 2FA challenge returned</response>
        /// <response code="401">Invalid credentials or unconfirmed email</response>
        [HttpPost("login-challenge")]
        [ProducesResponseType(typeof(LoginChallengeResponseDto), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        public async Task<IActionResult> LoginChallenge([FromBody] LoginChallengeDto model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);

            if (user == null)
                return Unauthorized(new { Status = "Error", Message = "Invalid email or password." });

            if (!await _userManager.IsEmailConfirmedAsync(user))
                return Unauthorized(new { Status = "Error", Message = "Please confirm your email before logging in." });

            if (!await _userManager.CheckPasswordAsync(user, model.Password))
                return Unauthorized(new { Status = "Error", Message = "Invalid email or password." });

            // Check if 2FA is enabled
            if (user.IsTwoFactorEnabled)
            {
                // Generate a challenge token (short-lived JWT for 2FA verification)
                var challengeToken = GenerateChallengeToken(user.Id, user.Email!);

                if (user.TwoFactorMethod == "Email")
                {
                    // Send magic login link
                    var loginToken = GenerateMagicLoginToken(user.Id, user.Email!);
                    var loginLink = Url.Action(nameof(VerifyEmailLogin), "Auth", new { token = loginToken }, Request.Scheme);
                    
                    var emailBody = await _viewRenderService.RenderToStringAsync("Emails/MagicLoginLink", loginLink);
                    await _emailService.SendEmailAsync(user.Email!, "Your Login Link", emailBody);
                }

                return Ok(new LoginChallengeResponseDto
                {
                    RequiresTwoFactor = true,
                    TwoFactorMethod = user.TwoFactorMethod ?? "Email",
                    ChallengeToken = challengeToken,
                    Message = user.TwoFactorMethod == "Email" 
                        ? "A login link has been sent to your email." 
                        : "Please enter the code from your authenticator app."
                });
            }

            // No 2FA - issue token directly
            var authClaims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.UserName!),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim("FirstName", user.FirstName),
                new Claim("UserId", user.Id),
                new Claim(ClaimTypes.Email, user.Email!)
            };

            var token = GetToken(authClaims);
            var tokenString = new JwtSecurityTokenHandler().WriteToken(token);

            // Set Cookies
            SetTokenCookie(tokenString, model.RememberMe);

            return Ok(new
            {
                RequiresTwoFactor = false,
                expiration = token.ValidTo
            });
        }

        /// <summary>
        /// Verify TOTP code from authenticator app (step 2 of 2FA login)
        /// </summary>
        /// <param name="model">Challenge token and 6-digit TOTP code</param>
        /// <returns>JWT token expiration on success</returns>
        /// <response code="200">Authentication successful, JWT cookie set</response>
        /// <response code="400">Authenticator not set up</response>
        /// <response code="401">Invalid challenge token or TOTP code</response>
        [HttpPost("verify-totp")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        public async Task<IActionResult> VerifyTotp([FromBody] VerifyTotpDto model)
        {
            // Validate challenge token
            var (userId, email) = ValidateChallengeToken(model.ChallengeToken);
            if (userId == null || email == null)
                return Unauthorized(new { Status = "Error", Message = "Invalid or expired challenge token." });

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null || user.Email != email)
                return Unauthorized(new { Status = "Error", Message = "User not found." });

            // Validate TOTP code
            if (string.IsNullOrEmpty(user.AuthenticatorSecretKey))
                return BadRequest(new { Status = "Error", Message = "Authenticator not set up." });

            if (!_totpService.ValidateCode(user.AuthenticatorSecretKey, model.Code))
                return Unauthorized(new { Status = "Error", Message = "Invalid verification code." });

            // Generate JWT token
            var authClaims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.UserName!),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim("FirstName", user.FirstName),
                new Claim("UserId", user.Id),
                new Claim(ClaimTypes.Email, user.Email!)
            };

            var token = GetToken(authClaims);
            var tokenString = new JwtSecurityTokenHandler().WriteToken(token);

            // Set Cookies
            SetTokenCookie(tokenString, model.RememberMe);

            return Ok(new
            {
                expiration = token.ValidTo
            });
        }

        /// <summary>
        /// Complete login via magic email link (step 2 of email-based 2FA)
        /// </summary>
        /// <param name="token">Magic login JWT token from email</param>
        /// <returns>Redirects to home on success, login page on error</returns>
        [HttpGet("verify-email-login")]
        [ProducesResponseType(StatusCodes.Status302Found)]
        public async Task<IActionResult> VerifyEmailLogin(string token)
        {
            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var key = Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]!);

                var validationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = true,
                    ValidIssuer = _configuration["Jwt:Issuer"],
                    ValidateAudience = true,
                    ValidAudience = _configuration["Jwt:Audience"],
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.Zero
                };

                var principal = tokenHandler.ValidateToken(token, validationParameters, out SecurityToken validatedToken);

                var userId = principal.FindFirst("UserId")?.Value;
                var email = principal.FindFirst(ClaimTypes.Email)?.Value;
                var purpose = principal.FindFirst("Purpose")?.Value;

                if (purpose != "MagicLogin" || string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(email))
                    return Redirect("/login?error=invalid_token");

                var user = await _userManager.FindByIdAsync(userId);
                if (user == null || user.Email != email)
                    return Redirect("/login?error=user_not_found");

                // Generate JWT token
                var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.UserName!),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                    new Claim("FirstName", user.FirstName),
                    new Claim("UserId", user.Id),
                    new Claim(ClaimTypes.Email, user.Email!)
                };

                var authToken = GetToken(authClaims);
                var jwtToken = new JwtSecurityTokenHandler().WriteToken(authToken);

                // Set Cookies (Magic Login is usually treated as a session or remembered? Let's assume session for safety, or we could pass a param)
                // For now, let's treat it as "Remember Me = false" (session only) unless we want to change url structure
                SetTokenCookie(jwtToken, false);

                // Redirect to home or dashboard since we are already authenticated via cookie
                return Redirect("/?magicLogin=success");
            }
            catch (SecurityTokenExpiredException)
            {
                return Redirect("/login?error=token_expired");
            }
            catch (Exception)
            {
                return Redirect("/login?error=invalid_token");
            }
        }

        /// <summary>
        /// Generate QR code for authenticator app setup
        /// </summary>
        /// <remarks>Requires authentication. Returns QR code data URI and manual entry key.</remarks>
        /// <returns>Authenticator setup data including QR code</returns>
        /// <response code="200">Setup data returned successfully</response>
        /// <response code="401">User not authenticated</response>
        /// <response code="404">User not found</response>
        [Authorize]
        [HttpPost("setup-authenticator")]
        [ProducesResponseType(typeof(AuthenticatorSetupDto), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public async Task<IActionResult> SetupAuthenticator()
        {
            var userId = User.FindFirst("UserId")?.Value;
            if (string.IsNullOrEmpty(userId))
                return Unauthorized();

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                return NotFound(new { Status = "Error", Message = "User not found." });

            // Generate new secret key
            var secretKey = _totpService.GenerateSecretKey();

            // Store the secret key (not confirmed yet)
            user.AuthenticatorSecretKey = secretKey;
            user.IsAuthenticatorConfirmed = false;
            await _userManager.UpdateAsync(user);

            // Generate QR code
            var qrCodeDataUri = _totpService.GenerateQrCodeDataUri(user.Email!, secretKey);
            var manualEntryKey = _totpService.FormatKeyForManualEntry(secretKey);

            return Ok(new AuthenticatorSetupDto
            {
                SecretKey = secretKey,
                QrCodeDataUri = qrCodeDataUri,
                ManualEntryKey = manualEntryKey
            });
        }

        /// <summary>
        /// Confirm authenticator setup by verifying the first TOTP code
        /// </summary>
        /// <remarks>Requires authentication. Enables 2FA with Authenticator method upon success.</remarks>
        /// <param name="model">6-digit verification code from authenticator app</param>
        /// <returns>Success message on confirmation</returns>
        /// <response code="200">Authenticator confirmed and 2FA enabled</response>
        /// <response code="400">Invalid code or authenticator not set up</response>
        /// <response code="401">User not authenticated</response>
        [Authorize]
        [HttpPost("confirm-authenticator")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        public async Task<IActionResult> ConfirmAuthenticator([FromBody] ConfirmAuthenticatorDto model)
        {
            var userId = User.FindFirst("UserId")?.Value;
            if (string.IsNullOrEmpty(userId))
                return Unauthorized();

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                return NotFound(new { Status = "Error", Message = "User not found." });

            if (string.IsNullOrEmpty(user.AuthenticatorSecretKey))
                return BadRequest(new { Status = "Error", Message = "Please set up authenticator first." });

            // Validate the code
            if (!_totpService.ValidateCode(user.AuthenticatorSecretKey, model.Code))
                return BadRequest(new { Status = "Error", Message = "Invalid verification code. Please try again." });

            // Confirm the authenticator and switch to authenticator method
            user.IsAuthenticatorConfirmed = true;
            user.TwoFactorMethod = "Authenticator";
            user.IsTwoFactorEnabled = true;
            await _userManager.UpdateAsync(user);

            return Ok(new { Status = "Success", Message = "Authenticator confirmed successfully!" });
        }

        /// <summary>
        /// Set preferred two-factor authentication method
        /// </summary>
        /// <remarks>Requires authentication. Valid methods: 'Authenticator' or 'Email'.</remarks>
        /// <param name="model">Preferred 2FA method</param>
        /// <returns>Success message on update</returns>
        /// <response code="200">2FA preference updated</response>
        /// <response code="400">Invalid method or authenticator not confirmed</response>
        /// <response code="401">User not authenticated</response>
        [Authorize]
        [HttpPost("set-2fa-preference")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        public async Task<IActionResult> Set2FAPreference([FromBody] Set2FAPreferenceDto model)
        {
            var userId = User.FindFirst("UserId")?.Value;
            if (string.IsNullOrEmpty(userId))
                return Unauthorized();

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                return NotFound(new { Status = "Error", Message = "User not found." });

            if (model.Method != "Authenticator" && model.Method != "Email")
                return BadRequest(new { Status = "Error", Message = "Invalid 2FA method. Use 'Authenticator' or 'Email'." });

            if (model.Method == "Authenticator" && !user.IsAuthenticatorConfirmed)
                return BadRequest(new { Status = "Error", Message = "Please set up and confirm your authenticator first." });

            user.TwoFactorMethod = model.Method;
            user.IsTwoFactorEnabled = true;
            await _userManager.UpdateAsync(user);

            return Ok(new { Status = "Success", Message = $"2FA method set to {model.Method}." });
        }

        /// <summary>
        /// Get current two-factor authentication status
        /// </summary>
        /// <remarks>Requires authentication.</remarks>
        /// <returns>2FA status including method and confirmation state</returns>
        /// <response code="200">2FA status returned</response>
        /// <response code="401">User not authenticated</response>
        /// <response code="404">User not found</response>
        [Authorize]
        [HttpGet("2fa-status")]
        [ProducesResponseType(typeof(TwoFactorStatusDto), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public async Task<IActionResult> Get2FAStatus()
        {
            var userId = User.FindFirst("UserId")?.Value;
            if (string.IsNullOrEmpty(userId))
                return Unauthorized();

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                return NotFound(new { Status = "Error", Message = "User not found." });

            return Ok(new TwoFactorStatusDto
            {
                IsTwoFactorEnabled = user.IsTwoFactorEnabled,
                TwoFactorMethod = user.TwoFactorMethod,
                IsAuthenticatorConfirmed = user.IsAuthenticatorConfirmed
            });
        }

        /// <summary>
        /// Disable two-factor authentication
        /// </summary>
        /// <remarks>Requires authentication. Disables all 2FA methods for the user.</remarks>
        /// <returns>Success message on disable</returns>
        /// <response code="200">2FA disabled successfully</response>
        /// <response code="401">User not authenticated</response>
        /// <response code="404">User not found</response>
        [Authorize]
        [HttpPost("disable-2fa")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public async Task<IActionResult> Disable2FA()
        {
            var userId = User.FindFirst("UserId")?.Value;
            if (string.IsNullOrEmpty(userId))
                return Unauthorized();

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                return NotFound(new { Status = "Error", Message = "User not found." });

            user.IsTwoFactorEnabled = false;
            user.TwoFactorMethod = null;
            await _userManager.UpdateAsync(user);

            return Ok(new { Status = "Success", Message = "Two-factor authentication has been disabled." });
        }

        /// <summary>
        /// Login with email and password (legacy endpoint)
        /// </summary>
        /// <remarks>Redirects to login-challenge internally. Use login-challenge for new integrations.</remarks>
        /// <param name="model">Login credentials</param>
        /// <returns>Authentication result</returns>
        [HttpPost("login")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        public async Task<IActionResult> Login([FromBody] LoginDto model)
        {
            // Redirect to login-challenge for consistency
            return await LoginChallenge(new LoginChallengeDto
            {
                Email = model.Email,
                Password = model.Password
            });
        }

        /// <summary>
        /// Refresh the JWT authentication token
        /// </summary>
        /// <remarks>Requires authentication. Issues a new JWT token before the current one expires.</remarks>
        /// <returns>New token expiration time</returns>
        /// <response code="200">Token refreshed successfully</response>
        /// <response code="401">User not authenticated</response>
        [Authorize]
        [HttpPost("refresh-token")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        public IActionResult RefreshToken()
        {
            var userId = User.FindFirst("UserId")?.Value;
            var userEmail = User.FindFirst(ClaimTypes.Email)?.Value;
            var userName = User.FindFirst(ClaimTypes.Name)?.Value;
            var userFirstName = User.FindFirst("FirstName")?.Value;

            if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(userEmail))
                return Unauthorized();

            var authClaims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, userName ?? userEmail),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim("FirstName", userFirstName ?? ""),
                new Claim("UserId", userId),
                new Claim(ClaimTypes.Email, userEmail)
            };

            var token = GetToken(authClaims);
            var tokenString = new JwtSecurityTokenHandler().WriteToken(token);

            // Refresh token -> Check if "remember me" was active?
            // Since we don't know the previous state easily without extra claims, 
            // we will default to Session cookie to be safe, OR check the existing cookie expiration.
            // Simplified approach: treating refresh as extending the CURRENT session type.
            // But we don't have that info easily. Let's assume we want to keep the user logged in.
            // BETTER: Check if the incoming request had a persistent cookie? 
            // Cookies doesn't tell us if it was persistent or session (browser handles that).
            // Let's set it as a Session cookie by default to respect the 10 min window logic, 
            // but if the user had "Remember Me", the browser might keep the old cookie? No, we are overwriting.
            // TO FIX: We need to know if we should persist.
            // For now: Let's set it as Session cookie. If the user closes the browser, they might lose it. 
            // But "Remember Me" really implies the *Refresh Token* (long lived) concept which we don't have.
            // We only have a short lived Access Token.
            // Our "Remember Me" implementation in Plan was: localStorage vs sessionStorage.
            // With Cookies: Persistent Cookie vs Session Cookie.
            // Since we can't easily know, let's Default to Session Cookie for security.
            SetTokenCookie(tokenString, false); 

            return Ok(new
            {
                expiration = token.ValidTo
            });
        }

        /// <summary>
        /// Logout and clear authentication cookies
        /// </summary>
        /// <remarks>Requires authentication. Removes JWT token cookies from browser.</remarks>
        /// <returns>Success message</returns>
        /// <response code="200">Logged out successfully</response>
        /// <response code="401">User not authenticated</response>
        [Authorize]
        [HttpPost("logout")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        public IActionResult Logout()
        {
            Response.Cookies.Delete("volet_auth");
            Response.Cookies.Delete("volet_session");
            return Ok(new { Message = "Logged out successfully" });
        }

        #region Helper Methods

        private void SetTokenCookie(string token, bool rememberMe)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Secure = true, // Ensure HTTPS
                SameSite = SameSiteMode.Strict,
                Expires = rememberMe ? DateTime.UtcNow.AddDays(7) : null // Persistent vs Session
            };

            Response.Cookies.Append("volet_auth", token, cookieOptions);

            // "Public" cookie for client-side logic (just expiration date)
            var sessionCookieOptions = new CookieOptions
            {
                HttpOnly = false, // JS can read this
                Secure = true,
                SameSite = SameSiteMode.Strict,
                Expires = rememberMe ? DateTime.UtcNow.AddDays(7) : null
            };

            // We need to decode the token to get the expiration, or just pass it in? 
            // Let's decode or just set a flag. Ideally checking real expiry from token is best.
            // But for simplicity, we can just let the client decode the JWT if we sent it? No, we don't send JWT to client.
            // So we write the Expiration Time to this public cookie.
            var handler = new JwtSecurityTokenHandler();
            var jwt = handler.ReadJwtToken(token);
            var exp = jwt.ValidTo;

            // Store as ISO string or timestamp
            // Simple string: "exp_timestamp"
            Response.Cookies.Append("volet_session", new DateTimeOffset(exp).ToUnixTimeSeconds().ToString(), sessionCookieOptions);
        }

        private string GenerateEmailConfirmationToken(string userId, string email)
        {
            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]!));

            var claims = new List<Claim>
            {
                new Claim("UserId", userId),
                new Claim(ClaimTypes.Email, email),
                new Claim("Purpose", "EmailConfirmation"),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                expires: DateTime.UtcNow.AddHours(24),
                claims: claims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private string GenerateChallengeToken(string userId, string email)
        {
            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]!));

            var claims = new List<Claim>
            {
                new Claim("UserId", userId),
                new Claim(ClaimTypes.Email, email),
                new Claim("Purpose", "2FAChallenge"),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                expires: DateTime.UtcNow.AddMinutes(10), // 10 minutes for 2FA
                claims: claims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private string GenerateMagicLoginToken(string userId, string email)
        {
            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]!));

            var claims = new List<Claim>
            {
                new Claim("UserId", userId),
                new Claim(ClaimTypes.Email, email),
                new Claim("Purpose", "MagicLogin"),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                expires: DateTime.UtcNow.AddMinutes(15), // 15 minutes for magic link
                claims: claims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private (string? userId, string? email) ValidateChallengeToken(string token)
        {
            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var key = Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]!);

                var validationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = true,
                    ValidIssuer = _configuration["Jwt:Issuer"],
                    ValidateAudience = true,
                    ValidAudience = _configuration["Jwt:Audience"],
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.Zero
                };

                var principal = tokenHandler.ValidateToken(token, validationParameters, out SecurityToken validatedToken);

                var userId = principal.FindFirst("UserId")?.Value;
                var email = principal.FindFirst(ClaimTypes.Email)?.Value;
                var purpose = principal.FindFirst("Purpose")?.Value;

                if (purpose != "2FAChallenge")
                    return (null, null);

                return (userId, email);
            }
            catch
            {
                return (null, null);
            }
        }

        private JwtSecurityToken GetToken(List<Claim> authClaims)
        {
            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]!));

            return new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                expires: DateTime.UtcNow.AddMinutes(10),
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
            );
        }

        #endregion
    }
}