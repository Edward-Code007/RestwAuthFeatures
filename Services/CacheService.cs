using Microsoft.Extensions.Caching.Memory;

namespace RestAuth.Services;

public interface ICacheService
{
    T? GetOrCreate<T>(string key, Func<T> factory, CacheEntryType cacheType = CacheEntryType.Default);
    void Set<T>(string key, T value, CacheEntryType cacheType = CacheEntryType.Default);
    void Remove(string key);
    void RemoveMultiple(params string[] keys);

    // Cache key builders for Users
    string UserByIdKey(Guid id);
    string UserByUsernameKey(string username);
    string EmailExistsKey(string email);
    string AllUsersKey { get; }
}

public enum CacheEntryType
{
    Default,
    Short
}

public class CacheService : ICacheService
{
    private readonly IMemoryCache _cache;
    private const string CacheKeyUserById = "user:id:";
    private const string CacheKeyUserByUsername = "user:username:";
    private const string CacheKeyEmailExists = "user:email:";
    private const string CacheKeyAllUsers = "users:all";

    public string AllUsersKey => CacheKeyAllUsers;
    public string UserByIdKey(Guid id) => $"{CacheKeyUserById}{id}";
    public string UserByUsernameKey(string username) => $"{CacheKeyUserByUsername}{username.ToLowerInvariant()}";
    public string EmailExistsKey(string email) => $"{CacheKeyEmailExists}{email.ToLowerInvariant()}";
    private static readonly MemoryCacheEntryOptions ShortCacheOptions = new()
    {
        AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(1),
        SlidingExpiration = TimeSpan.FromSeconds(30)
    };
    public CacheService(IMemoryCache cache)
    {
        _cache = cache;
    }
    public T? GetOrCreate<T>(string key, Func<T> factory, CacheEntryType cacheType = CacheEntryType.Default)
    {
        return _cache.GetOrCreate(key, entry =>
        {
            entry.SetOptions(GetCacheOptions(cacheType));
            return factory();
        });
    }
    public void Set<T>(string key, T value, CacheEntryType cacheType = CacheEntryType.Default)
    {
        _cache.Set(key, value, GetCacheOptions(cacheType));
    }
    public void Remove(string key)
    {
        _cache.Remove(key);
    }
    public void RemoveMultiple(params string[] keys)
    {
        foreach (var key in keys)
        {
            _cache.Remove(key);
        }
    }
    private static MemoryCacheEntryOptions GetCacheOptions(CacheEntryType cacheType)
    {
        return cacheType switch
        {
            CacheEntryType.Short => ShortCacheOptions,
            _ => DefaultCacheOptions
        };
    }
    private static readonly MemoryCacheEntryOptions DefaultCacheOptions = new()
    {
        AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(5),
        SlidingExpiration = TimeSpan.FromMinutes(2)
    };
}
