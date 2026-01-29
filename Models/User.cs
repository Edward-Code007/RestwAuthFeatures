namespace RestAuth.Models;

public class User
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public required string Username { get; set; }
    public required string PasswordHash { get; set; }
    public required string Email { get; set; }
    public List<string> Roles { get; set; } = ["User"];
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}

public class RefreshToken
{
    public required string Token { get; set; }
    public Guid UserId { get; set; }
    public DateTime ExpiresAt { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public bool IsRevoked { get; set; } = false;
    public required string FamilyId { get; set; }
    public bool IsUsed { get; set; } = false;
}

public class RefreshTokenResult
{
    public bool IsValid { get; private set; }
    public bool WasReused { get; private set; }
    public string? FamilyId { get; private set; }
    public RefreshToken? Token { get; private set; }

    public static RefreshTokenResult Valid(RefreshToken token)
        => new() { IsValid = true, Token = token };

    public static RefreshTokenResult Invalid()
        => new() { IsValid = false };

    public static RefreshTokenResult Reused(string familyId)
        => new() { IsValid = false, WasReused = true, FamilyId = familyId };
}
