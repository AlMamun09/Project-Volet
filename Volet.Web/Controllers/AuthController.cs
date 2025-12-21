using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Volet.Application.DTOs;
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

        public AuthController(
            UserManager<ApplicationUser> userManager, 
            IConfiguration configuration, 
            IEmailService emailService,
            IViewRenderService viewRenderService)
        {
            _userManager = userManager;
            _configuration = configuration;
            _emailService = emailService;
            _viewRenderService = viewRenderService;
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
                HasAcceptedNewsletterAndAnalytics = model.HasAcceptedNewsletterAndAnalytics
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
                    return BadRequest(new { Status = "Error", Message = "Invalid confirmation token." });

                var user = await _userManager.FindByIdAsync(userId);
                if (user == null || user.Email != email)
                    return BadRequest(new { Status = "Error", Message = "User not found." });

                if (user.EmailConfirmed)
                    return Redirect("/login?emailConfirmed=true&message=already");

                // Confirm the email
                user.EmailConfirmed = true;
                var result = await _userManager.UpdateAsync(user);

                if (result.Succeeded)
                {
                    return Redirect("/login?emailConfirmed=true");
                }

                return BadRequest(new { Status = "Error", Message = "Email confirmation failed." });
            }
            catch (SecurityTokenExpiredException)
            {
                return BadRequest(new { Status = "Error", Message = "Confirmation link has expired. Please request a new one." });
            }
            catch (Exception)
            {
                return BadRequest(new { Status = "Error", Message = "Invalid or expired confirmation link." });
            }
        }

        // POST: api/Auth/login
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginDto model)
        {
            // Find the user
            var user = await _userManager.FindByEmailAsync(model.Email);

            if (user == null)
                return Unauthorized(new { Status = "Error", Message = "Invalid email or password." });

            // Check if email is confirmed
            if (!await _userManager.IsEmailConfirmedAsync(user))
                return Unauthorized(new { Status = "Error", Message = "Please confirm your email before logging in." });

            // Validate password
            if (await _userManager.CheckPasswordAsync(user, model.Password))
            {
                // Create Claims (details inside the token)
                var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.UserName!),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                    new Claim("FirstName", user.FirstName),
                    new Claim("UserId", user.Id)
                };

                // Generate the Token
                var token = GetToken(authClaims);

                return Ok(new
                {
                    token = new JwtSecurityTokenHandler().WriteToken(token),
                    expiration = token.ValidTo
                });
            }

            return Unauthorized(new { Status = "Error", Message = "Invalid email or password." });
        }

        // Helper method to generate JWT for email confirmation
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
                expires: DateTime.UtcNow.AddHours(24), // 24 hours validity for email confirmation
                claims: claims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        // Helper method to generate JWT
        private JwtSecurityToken GetToken(List<Claim> authClaims)
        {
            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]!));

            return new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                expires: DateTime.Now.AddHours(3),
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
            );
        }
    }
}