using System.Security.Claims;
using RestAuth.Models;

namespace RestAuth.Endpoints;

public static class UserEndpoints
{
    public static IEndpointRouteBuilder MapUserEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet("/me", (ClaimsPrincipal user) =>
        {
            var userId = user.FindFirstValue(ClaimTypes.NameIdentifier);
            var username = user.FindFirstValue(ClaimTypes.Name);
            var email = user.FindFirstValue(ClaimTypes.Email);
            var roles = user.FindAll(ClaimTypes.Role).Select(c => c.Value).ToList();

            return Results.Ok(new UserResponse(
                Guid.Parse(userId!), username!, email!, roles));
        })
        .RequireAuthorization()
        .WithName("GetCurrentUser")
        .WithTags("Users")
        .WithDescription("Obtiene la información del usuario autenticado");

        return app;
    }
}
