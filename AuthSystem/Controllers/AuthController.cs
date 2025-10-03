using AuthSystem.Data;
using AuthSystem.DTOs;
using AuthSystem.Models;
using AuthSystem.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace AuthSystem.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly AppDbContext _db;
        private readonly IConfiguration _config;
        private readonly EmailService _email;

        public AuthController(AppDbContext db, IConfiguration config, EmailService email)
        {
            _db = db;
            _config = config;
            _email = email;
        }

        private Dictionary<string, string> GetMessages()
        {
            var lang = Request.Headers["Accept-Language"].ToString().ToLower();
            if (lang == "ar")
            {
                return new Dictionary<string, string>
                {
                    { "PasswordsNotMatch", "كلمات المرور غير متطابقة." },
                    { "UserExists", "المستخدم موجود بالفعل." },
                    { "UserRegistered", "تم إنشاء الحساب بنجاح." },
                    { "InvalidCredentials", "بيانات الدخول غير صحيحة." },
                    { "UserNotFound", "المستخدم غير موجود." },
                    { "ResetCodeSent", "تم إرسال كود إعادة التعيين على بريدك." },
                    { "InvalidOrExpired", "الكود غير صالح أو منتهي الصلاحية." },
                    { "PasswordReset", "تم إعادة تعيين كلمة المرور بنجاح." },
                    { "ProfileUpdated", "تم تحديث الملف الشخصي بنجاح." },
                    { "AccountDeleted", "تم حذف الحساب بنجاح." }
                };
            }
            else
            {
                return new Dictionary<string, string>
                {
                    { "PasswordsNotMatch", "Passwords do not match." },
                    { "UserExists", "User already exists." },
                    { "UserRegistered", "User registered successfully." },
                    { "InvalidCredentials", "Invalid credentials." },
                    { "UserNotFound", "User not found." },
                    { "ResetCodeSent", "Reset code sent to your email." },
                    { "InvalidOrExpired", "Invalid or expired code." },
                    { "PasswordReset", "Password reset successful." },
                    { "ProfileUpdated", "Profile updated successfully." },
                    { "AccountDeleted", "Account deleted successfully." }
                };
            }
        }

        private string GenerateJwtToken(User user)
        {
            var key = Encoding.UTF8.GetBytes(_config["Jwt:Key"]);
            var tokenHandler = new JwtSecurityTokenHandler();
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                    new Claim(ClaimTypes.Name, user.Name)
                }),
                Expires = DateTime.UtcNow.AddHours(2),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };
            return tokenHandler.WriteToken(tokenHandler.CreateToken(tokenDescriptor));
        }

        private string ComputeSha256Hash(string raw)
        {
            using var sha = SHA256.Create();
            return Convert.ToHexString(sha.ComputeHash(Encoding.UTF8.GetBytes(raw)));
        }

        private string GenerateNumericCode(int length)
        {
            using var rng = RandomNumberGenerator.Create();
            var bytes = new byte[length];
            rng.GetBytes(bytes);
            var sb = new StringBuilder(length);
            for (int i = 0; i < length; i++) sb.Append((bytes[i] % 10).ToString());
            return sb.ToString();
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterDto dto)
        {
            var messages = GetMessages();

            if (dto.Password != dto.ConfirmPassword)
                return BadRequest(new { message = messages["PasswordsNotMatch"] });

            if (await _db.Users.AnyAsync(u => u.EmailOrPhone == dto.EmailOrPhone))
                return BadRequest(new { message = messages["UserExists"] });

            var user = new User
            {
                Name = dto.Name,
                EmailOrPhone = dto.EmailOrPhone,
                PasswordHash = BCrypt.Net.BCrypt.HashPassword(dto.Password)
            };
            _db.Users.Add(user);
            await _db.SaveChangesAsync();

            return Ok(new { message = messages["UserRegistered"] });
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginDto dto)
        {
            var messages = GetMessages();

            var user = await _db.Users.FirstOrDefaultAsync(u => u.EmailOrPhone == dto.EmailOrPhone);
            if (user == null || !BCrypt.Net.BCrypt.Verify(dto.Password, user.PasswordHash))
                return Unauthorized(new { message = messages["InvalidCredentials"] });

            return Ok(new { token = GenerateJwtToken(user) });
        }

        [HttpPost("forgot-password")]
        public async Task<IActionResult> ForgotPassword([FromBody] ForgotDto dto)
        {
            var messages = GetMessages();

            var user = await _db.Users.FirstOrDefaultAsync(u => u.EmailOrPhone == dto.EmailOrPhone);
            if (user == null) return NotFound(new { message = messages["UserNotFound"] });

            var token = GenerateNumericCode(6);
            user.ResetTokenHash = ComputeSha256Hash(token);
            user.ResetTokenExpiry = DateTime.UtcNow.AddMinutes(15);
            await _db.SaveChangesAsync();

            await _email.SendEmailAsync(user.EmailOrPhone, "Reset Your Password", $"Your reset code is: <b>{token}</b>");

            return Ok(new { message = messages["ResetCodeSent"] });
        }

        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordDto dto)
        {
            var messages = GetMessages();

            if (dto.NewPassword != dto.ConfirmPassword)
                return BadRequest(new { message = messages["PasswordsNotMatch"] });

            var hash = ComputeSha256Hash(dto.Token);
            var user = await _db.Users.FirstOrDefaultAsync(u => u.ResetTokenHash == hash && u.ResetTokenExpiry > DateTime.UtcNow);
            if (user == null) return BadRequest(new { message = messages["InvalidOrExpired"] });

            user.PasswordHash = BCrypt.Net.BCrypt.HashPassword(dto.NewPassword);
            user.ResetTokenHash = null;
            user.ResetTokenExpiry = null;
            await _db.SaveChangesAsync();

            return Ok(new { message = messages["PasswordReset"] });
        }

        [Authorize]
        [HttpPut("update-profile")]
        public async Task<IActionResult> UpdateProfile([FromBody] UpdateProfileDto dto)
        {
            var messages = GetMessages();

            var userId = int.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
            var user = await _db.Users.FindAsync(userId);
            if (user == null) return NotFound();

            user.Name = dto.Name ?? user.Name;
            user.EmailOrPhone = dto.EmailOrPhone ?? user.EmailOrPhone;
            if (!string.IsNullOrEmpty(dto.Password))
                user.PasswordHash = BCrypt.Net.BCrypt.HashPassword(dto.Password);

            await _db.SaveChangesAsync();
            return Ok(new { message = messages["ProfileUpdated"] });
        }

        [Authorize]
        [HttpDelete("delete-account")]
        public async Task<IActionResult> DeleteAccount()
        {
            var messages = GetMessages();

            var userId = int.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
            var user = await _db.Users.FindAsync(userId);
            if (user == null) return NotFound();

            _db.Users.Remove(user);
            await _db.SaveChangesAsync();
            return Ok(new { message = messages["AccountDeleted"] });
        }
    }
}
