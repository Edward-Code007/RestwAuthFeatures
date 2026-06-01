using System.ComponentModel.DataAnnotations;

namespace RestAuth.Models;

public record RegisterRequest(
    [Required] string Username,
    [Required, EmailAddress] string Email,
    [Required, MinLength(6)] string Password
);

public record LoginRequest(
    [Required] string Username,
    [Required] string Password
);

public record RefreshRequest(
    [Required] string RefreshToken
);

public record AuthResponse(
    string AccessToken,
    string RefreshToken,
    DateTime ExpiresAt
);

public record UserResponse(
    Guid Id,
    string Username,
    string Email,
    List<string> Roles
);

public record RoleRequest(
    [Required] string Role
);
