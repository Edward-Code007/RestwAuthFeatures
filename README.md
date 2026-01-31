# RestAuth

API REST de autenticación y autorización construida con ASP.NET Core 10.0. Este proyecto demuestra la implementación de un sistema de autenticación completo basado en JWT con refresh tokens y control de acceso basado en roles (RBAC).

## Objetivo

Este proyecto tiene como finalidad demostrar conocimientos en:

- Implementación de autenticación y autorización en APIs REST
- Manejo de tokens JWT y refresh tokens
- Aplicación de buenas prácticas de seguridad en el desarrollo de software
- Arquitectura de APIs con ASP.NET Core y Minimal APIs
- Patrones de diseño como Dependency Injection, Repository Pattern y DTOs
- Implementación de Rate Limiting para protección contra abuso

## Tecnologías

- **Framework**: ASP.NET Core 10.0
- **Lenguaje**: C#
- **Autenticación**: JWT Bearer Tokens
- **Rate Limiting**: Built-in ASP.NET Core Rate Limiting (Sliding Window)
- **Documentación API**: OpenAPI/Swagger
- **Estilo de Endpoints**: Minimal APIs

## Features

### Autenticación

- Registro de usuarios con validación de email
- Login con credenciales usuario/contraseña
- Generación de tokens JWT de acceso (expiración configurable, por defecto 15 minutos)
- Generación y validación de refresh tokens (expiración configurable, por defecto 7 días)
- Revocación de tokens (logout)
- Logout de todas las sesiones (revoca todos los tokens del usuario)

### Seguridad

- Hash de contraseñas usando PBKDF2 con SHA-256 (100,000 iteraciones)
- Verificación de contraseñas con comparación de tiempo fijo (previene ataques de timing)
- Validación de firma JWT
- Validación de issuer y audience
- **Detección de reutilización de refresh tokens**: Seguimiento por familia de tokens para detectar robo
- Revocación automática de toda la familia de tokens cuando se detecta reutilización

### Rate Limiting

Implementación de rate limiting usando **Sliding Window** para proteger contra ataques de fuerza bruta y abuso de la API.

#### Configuración actual

| Política | Límite | Ventana | Endpoints |
|----------|--------|---------|-----------|
| Global | 100 req/min | Sliding Window (6 segmentos) | Todos |
| Auth | 10 req/min | Sliding Window (6 segmentos) | `/auth/login`, `/auth/register` |

#### Características

- **Sliding Window**: Distribución más suave que Fixed Window, evita el problema del "borde de ventana"
- **Particionado por IP**: Cada cliente tiene su propio contador independiente
- **Respuesta 429**: Cuando se excede el límite, retorna `HTTP 429 Too Many Requests` con header `Retry-After`
- **Sin cola**: Las requests excedentes se rechazan inmediatamente (`QueueLimit = 0`)

#### Respuesta cuando se excede el límite

```json
HTTP/1.1 429 Too Many Requests
Retry-After: 60

{
  "error": "Demasiadas solicitudes. Por favor, intenta de nuevo más tarde.",
  "retryAfterSeconds": 60
}
```

### Autorización

- Control de acceso basado en roles (RBAC)
- Tres políticas predefinidas:
  - `AdminOnly` - Solo administradores
  - `Authenticated` - Cualquier usuario autenticado
  - `UserOrAdmin` - Rol de Usuario o Admin

### Gestión de Administración

- Listar todos los usuarios
- Obtener usuario por ID
- Agregar roles a usuarios
- Eliminar roles de usuarios
- Eliminar usuarios (con protección contra auto-eliminación)

## Estructura del Proyecto

```
RestAuth/
├── Program.cs                    # Punto de entrada de la aplicación
├── RestAuth.csproj               # Archivo de proyecto con dependencias
├── RestAuth.http                 # Archivo de pruebas HTTP
├── appsettings.json              # Configuración JWT y general
├── appsettings.Development.json  # Configuración de desarrollo
│
├── Models/
│   ├── User.cs                   # Entidad User, RefreshToken, RefreshTokenResult
│   └── AuthDtos.cs               # DTOs de Request/Response
│
├── Services/
│   ├── ITokenService.cs          # Interfaz de generación y validación de tokens
│   ├── TokenService.cs           # Implementación de JWT y refresh tokens
│   ├── IUserService.cs           # Contrato de gestión de usuarios
│   └── UserService.cs            # Lógica de CRUD y autenticación de usuarios
│
├── Endpoints/
│   ├── AuthEndpoints.cs          # Rutas /auth/* (register, login, refresh, revoke)
│   ├── AdminEndpoints.cs         # Rutas /admin/* (gestión de usuarios)
│   └── UserEndpoints.cs          # Endpoint /me (info del usuario actual)
│
└── Properties/
    └── launchSettings.json       # Configuración de lanzamiento
```

## Configuración

### JWT (appsettings.json)

```json
{
  "Jwt": {
    "Key": "TuClaveSecretaSuperSeguraDeAlMenos32Caracteres!",
    "Issuer": "RestAuthAPI",
    "Audience": "RestAuthClients",
    "AccessTokenExpirationMinutes": 15,
    "RefreshTokenExpirationDays": 7
  }
}
```

## API Endpoints

### Autenticación (`/auth`)

| Método | Endpoint | Descripción | Auth Requerida |
|--------|----------|-------------|----------------|
| POST | `/auth/register` | Registrar nuevo usuario | No |
| POST | `/auth/login` | Iniciar sesión | No |
| POST | `/auth/refresh` | Renovar access token | No |
| POST | `/auth/revoke` | Revocar refresh token | No |
| POST | `/auth/logout-all` | Revocar todos los tokens del usuario | Sí |

### Usuario (`/me`)

| Método | Endpoint | Descripción | Auth Requerida |
|--------|----------|-------------|----------------|
| GET | `/me` | Obtener información del usuario actual | Sí |

### Administración (`/admin`)

| Método | Endpoint | Descripción | Auth Requerida |
|--------|----------|-------------|----------------|
| GET | `/admin/users` | Listar todos los usuarios | Admin |
| GET | `/admin/users/{id}` | Obtener usuario por ID | Admin |
| POST | `/admin/users/{id}/roles` | Agregar rol a usuario | Admin |
| DELETE | `/admin/users/{id}/roles/{role}` | Eliminar rol de usuario | Admin |
| DELETE | `/admin/users/{id}` | Eliminar usuario | Admin |

## Ejecución

### Requisitos

- .NET 10.0 SDK

### Ejecutar en desarrollo

```bash
dotnet run
```

La API estará disponible en:
- HTTP: `http://localhost:5000`
- HTTPS: `https://localhost:5001`

### Usuario Admin por defecto

Al iniciar la aplicación se crea un usuario administrador:
- **Usuario**: `admin`
- **Contraseña**: `admin123`

## Ejemplos de Uso

### Registro

```http
POST /auth/register
Content-Type: application/json

{
  "username": "usuario",
  "email": "usuario@ejemplo.com",
  "password": "contraseña123"
}
```

### Login

```http
POST /auth/login
Content-Type: application/json

{
  "username": "usuario",
  "password": "contraseña123"
}
```

### Refresh Token

```http
POST /auth/refresh
Content-Type: application/json

{
  "refreshToken": "tu-refresh-token"
}
```

### Obtener Usuario Actual

```http
GET /me
Authorization: Bearer tu-access-token
```

## Conceptos de Seguridad Demostrados

- **Zero clock skew** en validación de tokens (previene ataques de replay)
- **Validación de lifetime** de tokens habilitada
- **Detección de reutilización de refresh tokens** basada en familias de tokens
- **Logging de seguridad** para eventos de reutilización de tokens sospechosos
- **Comparación de tiempo constante** para verificación de contraseñas
- **Rate Limiting con Sliding Window** para protección contra fuerza bruta y DDoS
- **Límites diferenciados** por tipo de endpoint (más restrictivo en autenticación)
