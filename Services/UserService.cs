using System.Collections.Concurrent;
using System.Security.Cryptography;
using RestAuth.Models;

namespace RestAuth.Services;

public interface IUserService
{
    User? GetById(Guid id);
    User? GetByUsername(string username);

    Task<User?> GetByEmail(string email);
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
    private readonly ICacheService _cache;

    public UserService(ICacheService cache)
    {
        _cache = cache;

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

    public User? GetById(Guid id)
    {
        var cacheKey = _cache.UserByIdKey(id);

        return _cache.GetOrCreate(cacheKey, () =>
            _users.TryGetValue(id, out var user) ? user : null);
    }

    public User? GetByUsername(string username)
    {
        var cacheKey = _cache.UserByUsernameKey(username);

        return _cache.GetOrCreate(cacheKey, () =>
            _users.Values.FirstOrDefault(u =>
                u.Username.Equals(username, StringComparison.OrdinalIgnoreCase)));
    }

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
        
        _cache.Remove(_cache.AllUsersKey);

        _cache.Set(_cache.UserByIdKey(user.Id), user);
        _cache.Set(_cache.UserByUsernameKey(username), user);
        _cache.Set(_cache.EmailExistsKey(email), true);

        return user;
    }

    public bool UsernameExists(string username) =>
        GetByUsername(username) != null;

    public bool EmailExists(string email)
    {
        var cacheKey = _cache.EmailExistsKey(email);

        return _cache.GetOrCreate(cacheKey, () =>
            _users.Values.Any(u =>
                u.Email.Equals(email, StringComparison.OrdinalIgnoreCase)));
    }

    public IEnumerable<User> GetAll()
    {
        return _cache.GetOrCreate(_cache.AllUsersKey, () =>
            _users.Values.ToList(), CacheEntryType.Short) ?? [];
    }

    public bool AddRole(Guid userId, string role)
    {
        if (!_users.TryGetValue(userId, out var user))
            return false;

        if (user.Roles.Contains(role, StringComparer.OrdinalIgnoreCase))
            return true;

        user.Roles.Add(role);

        InvalidateUserCache(user);

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

        InvalidateUserCache(user);

        return true;
    }

    public bool DeleteUser(Guid userId)
    {
        if (_users.TryRemove(userId, out var user))
        {
            _cache.RemoveMultiple(
                _cache.UserByIdKey(userId),
                _cache.UserByUsernameKey(user.Username),
                _cache.EmailExistsKey(user.Email),
                _cache.AllUsersKey
            );
            return true;
        }
        return false;
    }

    private void InvalidateUserCache(User user)
    {
        _cache.RemoveMultiple(
            _cache.UserByIdKey(user.Id),
            _cache.UserByUsernameKey(user.Username),
            _cache.AllUsersKey
        );
    }

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

  public async Task<User?> GetByEmail(string email)
  {
    var user = this._users.Values.FirstOrDefault(x => x.Email == email);
    return user;
  }
}
