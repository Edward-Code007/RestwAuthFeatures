using System.Collections.Concurrent;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using RestAuth.Models;

namespace RestAuth.Services;

public interface ITokenService
{
    string GenerateAccessToken(User user);
    RefreshToken GenerateRefreshToken(Guid userId);
    RefreshToken GenerateRefreshToken(Guid userId, string familyId);
    RefreshTokenResult ValidateAndUseRefreshToken(string token);
    bool RevokeRefreshToken(string token);
    void RevokeTokenFamily(string familyId);
    void RevokeAllUserTokens(Guid userId);
    ClaimsPrincipal? ValidateAccessToken(string token);
}

public class TokenService : ITokenService
{
    private readonly IConfiguration _configuration;
    private readonly ConcurrentDictionary<string, RefreshToken> _refreshTokens = new();

    public TokenService(IConfiguration configuration)
    {
        _configuration = configuration;
    }

    public string GenerateAccessToken(User user)
    {
        var key = new SymmetricSecurityKey(
            Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]!));

        var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new(ClaimTypes.Name, user.Username),
            new(ClaimTypes.Email, user.Email),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };

        foreach (var role in user.Roles)
        {
            claims.Add(new Claim(ClaimTypes.Role, role));
        }

        var expirationMinutes = int.Parse(
            _configuration["Jwt:AccessTokenExpirationMinutes"] ?? "15");

        var token = new JwtSecurityToken(
            issuer: _configuration["Jwt:Issuer"],
            audience: _configuration["Jwt:Audience"],
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(expirationMinutes),
            signingCredentials: credentials
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    public RefreshToken GenerateRefreshToken(Guid userId)
    {
        return GenerateRefreshToken(userId, Guid.NewGuid().ToString());
    }

    public RefreshToken GenerateRefreshToken(Guid userId, string familyId)
    {
        var expirationDays = int.Parse(
            _configuration["Jwt:RefreshTokenExpirationDays"] ?? "7");

        var refreshToken = new RefreshToken
        {
            Token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)),
            UserId = userId,
            FamilyId = familyId,
            ExpiresAt = DateTime.UtcNow.AddDays(expirationDays),
            IsUsed = false
        };

        _refreshTokens[refreshToken.Token] = refreshToken;
        return refreshToken;
    }

    public RefreshTokenResult ValidateAndUseRefreshToken(string token)
    {
        if (!_refreshTokens.TryGetValue(token, out var refreshToken))
            return RefreshTokenResult.Invalid();

        if (refreshToken.IsRevoked || refreshToken.ExpiresAt < DateTime.UtcNow)
            return RefreshTokenResult.Invalid();

        if (refreshToken.IsUsed)
        {
            RevokeTokenFamily(refreshToken.FamilyId);
            return RefreshTokenResult.Reused(refreshToken.FamilyId);
        }

        refreshToken.IsUsed = true;

        return RefreshTokenResult.Valid(refreshToken);
    }

    public bool RevokeRefreshToken(string token)
    {
        if (!_refreshTokens.TryGetValue(token, out var refreshToken))
            return false;

        refreshToken.IsRevoked = true;
        return true;
    }

    public void RevokeTokenFamily(string familyId)
    {
        var familyTokens = _refreshTokens.Values
            .Where(t => t.FamilyId == familyId);

        foreach (var token in familyTokens)
        {
            token.IsRevoked = true;
        }
    }

    public void RevokeAllUserTokens(Guid userId)
    {
        var userTokens = _refreshTokens.Values
            .Where(t => t.UserId == userId);

        foreach (var token in userTokens)
        {
            token.IsRevoked = true;
        }
    }

    public ClaimsPrincipal? ValidateAccessToken(string token)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]!);

        try
        {
            return tokenHandler.ValidateToken(token, new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateIssuer = true,
                ValidIssuer = _configuration["Jwt:Issuer"],
                ValidateAudience = true,
                ValidAudience = _configuration["Jwt:Audience"],
                ValidateLifetime = false
            }, out _);
        }
        catch
        {
            return null;
        }
    }
}
