namespace AuthSystem.Models
{
    public class User
    {
        public int Id { get; set; }
        public string Name { get; set; } = null!;
        public string EmailOrPhone { get; set; } = null!;
        public string PasswordHash { get; set; } = null!;
        public string? ResetTokenHash { get; set; }
        public DateTime? ResetTokenExpiry { get; set; }
    }
}
