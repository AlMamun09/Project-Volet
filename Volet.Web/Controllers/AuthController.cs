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
    [Route("api/[controller]")]
    [ApiController]
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

        // POST: api/Auth/register
        [HttpPost("register")]
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

        // GET: api/Auth/confirm-email
        [HttpGet("confirm-email")]
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

        // POST: api/Auth/login-challenge
        // First step of login - validates credentials and returns 2FA method
        [HttpPost("login-challenge")]
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

            return Ok(new
            {
                RequiresTwoFactor = false,
                token = new JwtSecurityTokenHandler().WriteToken(token),
                expiration = token.ValidTo
            });
        }

        // POST: api/Auth/verify-totp
        // Verify TOTP code from Google Authenticator
        [HttpPost("verify-totp")]
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

            return Ok(new
            {
                token = new JwtSecurityTokenHandler().WriteToken(token),
                expiration = token.ValidTo
            });
        }

        // GET: api/Auth/verify-email-login
        // Verify magic login link from email
        [HttpGet("verify-email-login")]
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

                // Redirect to a page that will store the token and redirect to home
                return Redirect($"/login?magicLogin=success&token={jwtToken}");
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

        // POST: api/Auth/setup-authenticator
        // Generate QR code for Google Authenticator setup
        [Authorize]
        [HttpPost("setup-authenticator")]
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

        // POST: api/Auth/confirm-authenticator
        // Confirm authenticator setup by verifying first code
        [Authorize]
        [HttpPost("confirm-authenticator")]
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

        // POST: api/Auth/set-2fa-preference
        // Set user's preferred 2FA method
        [Authorize]
        [HttpPost("set-2fa-preference")]
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

        // GET: api/Auth/2fa-status
        // Get current 2FA status
        [Authorize]
        [HttpGet("2fa-status")]
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

        // POST: api/Auth/disable-2fa
        // Disable 2FA for the user
        [Authorize]
        [HttpPost("disable-2fa")]
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

        // POST: api/Auth/login (keep for backward compatibility, but redirects to login-challenge)
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginDto model)
        {
            // Redirect to login-challenge for consistency
            return await LoginChallenge(new LoginChallengeDto
            {
                Email = model.Email,
                Password = model.Password
            });
        }

        // POST: api/Auth/refresh-token
        [Authorize]
        [HttpPost("refresh-token")]
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

            return Ok(new
            {
                token = new JwtSecurityTokenHandler().WriteToken(token),
                expiration = token.ValidTo
            });
        }

        #region Helper Methods

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