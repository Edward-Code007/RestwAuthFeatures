using System.Runtime.CompilerServices;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Http.HttpResults;
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
            if (userService.UsernameExists(request.Username) || userService.EmailExists(request.Email))
                return Results.BadRequest(new { error = "El Nombre de usuario o Email ya existe" });

            var user = userService.Register(request.Username, request.Email, request.Password);

            return Results.Created($"/users/{user.Id}", new UserResponse(
                user.Id, user.Username, user.Email, user.Roles));
        })
        .WithName("Register")
        .WithDescription("Registra un nuevo usuario")
        .RequireRateLimiting("auth");

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
        .WithDescription("Inicia sesión y obtiene tokens")
        .RequireRateLimiting("auth");

        group.MapPost("/refresh", (RefreshRequest request, IUserService userService, ITokenService tokenService, ILogger<Program> logger) =>
        {
            var result = tokenService.ValidateAndUseRefreshToken(request.RefreshToken);

            if (result.WasReused)
            {
                logger.LogWarning(
                    "Refresh token reuse detected for family {FamilyId}. Possible token theft.",
                    result.FamilyId);
                return Results.Unauthorized();
            }

            if (!result.IsValid)
                return Results.Unauthorized();

            var user = userService.GetById(result.Token!.UserId);

            if (user == null)
                return Results.Unauthorized();

            var newAccessToken = tokenService.GenerateAccessToken(user);
            var newRefreshToken = tokenService.GenerateRefreshToken(user.Id, result.Token.FamilyId);

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

        group.MapPost("/logout-all", (ClaimsPrincipal user, ITokenService tokenService) =>
        {
            var userId = Guid.Parse(user.FindFirstValue(ClaimTypes.NameIdentifier)!);
            tokenService.RevokeAllUserTokens(userId);

            return Results.Ok(new { message = "Todas las sesiones han sido cerradas" });
        })
        .RequireAuthorization()
        .WithName("LogoutAll")
        .WithDescription("Revoca todos los refresh tokens del usuario (logout de todas las sesiones)");

        group.MapGet("google/signup", () => Results.Challenge(
            new AuthenticationProperties { RedirectUri = "/auth/google/register" }
            , [GoogleDefaults.AuthenticationScheme]));

        group.MapGet("google/register", async (HttpContext ctx, IUserService userService, ITokenService tokenService) =>
        {
            var result = await ctx.AuthenticateAsync("temp");
            if (!result.Succeeded)
            {
                return Results.Forbid();
            }
            var email = result.Principal!.FindFirst(ClaimTypes.Email)?.Value;
            var name = result.Principal!.FindFirst(ClaimTypes.GivenName)?.Value;
            var lastname = result.Principal!.FindFirst(ClaimTypes.Surname)?.Value;
            await ctx.SignOutAsync();
            if (!userService.EmailExists(email!))
            {
                var user = userService.Register($"{name!} {lastname!}", email!, "");
                var token = tokenService.GenerateAccessToken(user);
                var refreshToken = tokenService.GenerateRefreshToken(user.Id);
                return Results.Created("http://localhost:5224/auth/google/register", new
                {
                    message = "Usuario Creado con exito",
                    statuscode = 201,
                    token,
                    refreshToken
                });
            }
            else
            {
                var user = await userService.GetByEmail(email!);
                var token = tokenService.GenerateAccessToken(user!);
                var refreshToken = tokenService.GenerateRefreshToken(user!.Id);
                return Results.Ok(new
                {
                    message = "Usuario Autenticado",
                    statuscode = 200,
                    token,
                    refreshToken
                });
            }

        })
         .WithName("LogInWGoogle")
         .WithDescription("Autentica al Usuario a traves del Proveedor de Identidades de Google");
        return app;
    }
}
