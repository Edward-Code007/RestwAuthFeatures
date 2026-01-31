using System.Security.Claims;
using RestAuth.Models;
using RestAuth.Services;

namespace RestAuth.Endpoints;

public static class AdminEndpoints
{
    public static IEndpointRouteBuilder MapAdminEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/admin")
            .WithTags("Administration")
            .RequireAuthorization("AdminOnly");

        group.MapGet("/users",IResult (IUserService userService) =>
        {
            var users = userService.GetAll()
                .Select(u => new UserResponse(u.Id, u.Username, u.Email, u.Roles));
            
            return Results.Ok(users);
        })
        .WithName("GetAllUsers")
        .WithDescription("Lista todos los usuarios");

        group.MapGet("/users/{id:guid}", (Guid id, IUserService userService) =>
        {
            var user = userService.GetById(id);

            return user == null
                ? Results.NotFound(new { error = "Usuario no encontrado" })
                : Results.Ok(new UserResponse(user.Id, user.Username, user.Email, user.Roles));
        })
        .WithName("GetUserById")
        .WithDescription("Obtiene un usuario por su ID");

        group.MapPost("/users/{id:guid}/roles", (Guid id, RoleRequest request, IUserService userService) =>
        {
            var user = userService.GetById(id);

            if (user == null)
                return Results.NotFound(new { error = "Usuario no encontrado" });

            userService.AddRole(id, request.Role);

            return Results.Ok(new UserResponse(user.Id, user.Username, user.Email, user.Roles));
        })
        .WithName("AddRoleToUser")
        .WithDescription("Agrega un rol a un usuario");

        group.MapDelete("/users/{id:guid}/roles/{role}", (Guid id, string role, IUserService userService) =>
        {
            var user = userService.GetById(id);

            if (user == null)
                return Results.NotFound(new { error = "Usuario no encontrado" });

            userService.RemoveRole(id, role);

            return Results.Ok(new UserResponse(user.Id, user.Username, user.Email, user.Roles));
        })
        .WithName("RemoveRoleFromUser")
        .WithDescription("Quita un rol de un usuario");

        group.MapDelete("/users/{id:guid}", (Guid id, IUserService userService, ClaimsPrincipal currentUser) =>
        {
            var currentUserId = Guid.Parse(currentUser.FindFirstValue(ClaimTypes.NameIdentifier)!);

            if (id == currentUserId)
                return Results.BadRequest(new { error = "No puedes eliminarte a ti mismo" });

            var deleted = userService.DeleteUser(id);

            return deleted
                ? Results.Ok(new { message = "Usuario eliminado" })
                : Results.NotFound(new { error = "Usuario no encontrado" });
        })
        .WithName("DeleteUser")
        .WithDescription("Elimina un usuario");

        return app;
    }
}
