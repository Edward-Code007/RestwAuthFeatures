using System.Collections.Concurrent;
using System.Security.Cryptography;
using RestAuth.Models;

namespace RestAuth.Services;

public interface IUserService
{
    User? GetById(Guid id);
    User? GetByUsername(string username);
    User? ValidateCredentials(string username, string password);
    User Register(string username, string email, string password);
    bool UsernameExists(string username);
    bool EmailExists(string email);
    IEnumerable<User> GetAll();
    bool AddRole(Guid userId, string role);
    bool RemoveRole(Guid userId, string role);
    bool DeleteUser(Guid userId);
}

public class UserService : IUserService
{
    private readonly ConcurrentDictionary<Guid, User> _users = new();

    public UserService()
    {
        var adminId = Guid.NewGuid();
        _users[adminId] = new User
        {
            Id = adminId,
            Username = "admin",
            Email = "admin@example.com",
            PasswordHash = HashPassword("admin123"),
            Roles = ["User", "Admin"]
        };
    }

    public User? GetById(Guid id) =>
        _users.TryGetValue(id, out var user) ? user : null;

    public User? GetByUsername(string username) =>
        _users.Values.FirstOrDefault(u =>
            u.Username.Equals(username, StringComparison.OrdinalIgnoreCase));

    public User? ValidateCredentials(string username, string password)
    {
        var user = GetByUsername(username);
        if (user == null) return null;

        return VerifyPassword(password, user.PasswordHash) ? user : null;
    }

    public User Register(string username, string email, string password)
    {
        var user = new User
        {
            Username = username,
            Email = email,
            PasswordHash = HashPassword(password)
        };

        _users[user.Id] = user;
        return user;
    }

    public bool UsernameExists(string username) =>
        _users.Values.Any(u =>
            u.Username.Equals(username, StringComparison.OrdinalIgnoreCase));

    public bool EmailExists(string email) =>
        _users.Values.Any(u =>
            u.Email.Equals(email, StringComparison.OrdinalIgnoreCase));

    public IEnumerable<User> GetAll() => _users.Values;

    public bool AddRole(Guid userId, string role)
    {
        if (!_users.TryGetValue(userId, out var user))
            return false;

        if (user.Roles.Contains(role, StringComparer.OrdinalIgnoreCase))
            return true;

        user.Roles.Add(role);
        return true;
    }

    public bool RemoveRole(Guid userId, string role)
    {
        if (!_users.TryGetValue(userId, out var user))
            return false;

        var existingRole = user.Roles.FirstOrDefault(r =>
            r.Equals(role, StringComparison.OrdinalIgnoreCase));

        if (existingRole == null)
            return true;

        user.Roles.Remove(existingRole);
        return true;
    }

    public bool DeleteUser(Guid userId) =>
        _users.TryRemove(userId, out _);

    private static string HashPassword(string password)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        var hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, 100000, HashAlgorithmName.SHA256, 32);
        return $"{Convert.ToBase64String(salt)}:{Convert.ToBase64String(hash)}";
    }

    private static bool VerifyPassword(string password, string storedHash)
    {
        var parts = storedHash.Split(':');
        if (parts.Length != 2) return false;

        var salt = Convert.FromBase64String(parts[0]);
        var hash = Convert.FromBase64String(parts[1]);
        var computedHash = Rfc2898DeriveBytes.Pbkdf2(password, salt, 100000, HashAlgorithmName.SHA256, 32);

        return CryptographicOperations.FixedTimeEquals(hash, computedHash);
    }
}
