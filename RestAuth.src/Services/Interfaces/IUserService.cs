using RestAuth.Models;

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