using RestAuth.Models;

public interface ITokenService
{
    string GenerateAccessToken(User user);
    RefreshToken GenerateRefreshToken(Guid userId);
    RefreshToken GenerateRefreshToken(Guid userId, string familyId);
    RefreshTokenResult ValidateAndUseRefreshToken(string token);
    bool RevokeRefreshToken(string token);
    void RevokeTokenFamily(string familyId);
    void RevokeAllUserTokens(Guid userId);
}
