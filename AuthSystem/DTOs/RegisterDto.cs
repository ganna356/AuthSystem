namespace AuthSystem.DTOs
{
    public class RegisterDto
    {
        public string Name { get; set; } = null!;
        public string EmailOrPhone { get; set; } = null!;
        public string Password { get; set; } = null!;
        public string ConfirmPassword { get; set; } = null!;
    }
}
