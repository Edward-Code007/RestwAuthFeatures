using RestAuth.Models;
using RestAuth.Services;

namespace RestAuth.Endpoints;

public static class AuthEndpoints
{
    public static IEndpointRouteBuilder MapAuthEndpoints(this IEndpointRouteBuilder app, IConfiguration config)
    {
        var group = app.MapGroup("/auth").WithTags("Authentication");

        group.MapPost("/register", (RegisterRequest request, IUserService userService) =>
        {
            if (userService.UsernameExists(request.Username))
                return Results.BadRequest(new { error = "El nombre de usuario ya existe" });

            if (userService.EmailExists(request.Email))
                return Results.BadRequest(new { error = "El email ya está registrado" });

            var user = userService.Register(request.Username, request.Email, request.Password);

            return Results.Created($"/users/{user.Id}", new UserResponse(
                user.Id, user.Username, user.Email, user.Roles));
        })
        .WithName("Register")
        .WithDescription("Registra un nuevo usuario");

        group.MapPost("/login", (LoginRequest request, IUserService userService, ITokenService tokenService) =>
        {
            var user = userService.ValidateCredentials(request.Username, request.Password);

            if (user == null)
                return Results.Unauthorized();

            var accessToken = tokenService.GenerateAccessToken(user);
            var refreshToken = tokenService.GenerateRefreshToken(user.Id);

            return Results.Ok(new AuthResponse(
                accessToken,
                refreshToken.Token,
                DateTime.UtcNow.AddMinutes(
                    int.Parse(config["Jwt:AccessTokenExpirationMinutes"] ?? "15"))));
        })
        .WithName("Login")
        .WithDescription("Inicia sesión y obtiene tokens");

        group.MapPost("/refresh", (RefreshRequest request, IUserService userService, ITokenService tokenService) =>
        {
            var storedToken = tokenService.GetRefreshToken(request.RefreshToken);

            if (storedToken == null)
                return Results.Unauthorized();

            var user = userService.GetById(storedToken.UserId);

            if (user == null)
                return Results.Unauthorized();

            tokenService.RevokeRefreshToken(request.RefreshToken);

            var newAccessToken = tokenService.GenerateAccessToken(user);
            var newRefreshToken = tokenService.GenerateRefreshToken(user.Id);

            return Results.Ok(new AuthResponse(
                newAccessToken,
                newRefreshToken.Token,
                DateTime.UtcNow.AddMinutes(
                    int.Parse(config["Jwt:AccessTokenExpirationMinutes"] ?? "15"))));
        })
        .WithName("Refresh")
        .WithDescription("Renueva el access token usando el refresh token");

        group.MapPost("/revoke", (RefreshRequest request, ITokenService tokenService) =>
        {
            var revoked = tokenService.RevokeRefreshToken(request.RefreshToken);

            return revoked
                ? Results.Ok(new { message = "Token revocado exitosamente" })
                : Results.BadRequest(new { error = "Token no encontrado o ya revocado" });
        })
        .WithName("Revoke")
        .WithDescription("Revoca un refresh token (logout)");

        return app;
    }
}
