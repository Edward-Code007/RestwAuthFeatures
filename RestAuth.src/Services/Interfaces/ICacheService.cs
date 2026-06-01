using RestAuth.Services;

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