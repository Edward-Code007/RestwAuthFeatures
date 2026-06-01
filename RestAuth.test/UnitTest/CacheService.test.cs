using Microsoft.Extensions.Caching.Memory;
using Moq;
using RestAuth.Models;
using RestAuth.Services;
public class CacheServiceTest
{

    [Fact]
    public void GetOrCreate_ShouldRetrieveLogWhenExists()
    {
        //Arrange
        var memoCache = new MemoryCache(new MemoryCacheOptions());
        var cacheService = new CacheService(memoCache);
        memoCache.Set("test", new User() { Email = "test@mail.com", PasswordHash = "", Username = "testuser" });
        //Act
        var retrieveUser = cacheService.GetOrCreate<User>("test", () => new User() { Email = "test@mail.com", PasswordHash = "", Username = "testuser" });
        //Assert
        Assert.True(true);
        Assert.IsType<User>(retrieveUser);
        Assert.Equal("testuser", retrieveUser.Username);
    }
    [Fact]
    public void GetOrCreate_ShouldCreateLogWhenNotExist()
    {
        //Arrange
        User? user;
        var memoCache = new MemoryCache(new MemoryCacheOptions());
        var cacheService = new CacheService(memoCache);
        cacheService.GetOrCreate<User>("test", () => new User() { Email = "test@mail.com", PasswordHash = "", Username = "testuser" });
        //Act
        var userExists = memoCache.TryGetValue("test", out user);
        //Assert
        Assert.True(userExists);
        Assert.IsType<User>(user);
        Assert.Equal("testuser", user.Username);
    }
    [Fact]
    public void TestName()
    {
        // Given
    
        // When
    
        // Then
    }
}