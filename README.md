# ASP.NET Core Auth Kit

This project is a starter kit that demonstrates JWT (JSON Web Token) based authentication and the Refresh Token mechanism in ASP.NET Core. It consists of a Web API (`Api`) and an MVC client (`UI`) that consumes it. The primary goal is to provide a clear, practical example of how to manage modern authentication flows in a decoupled architecture.


## 🚀 Purpose & Key Features

This project aims to establish a secure authentication flow between a client and a server. The API generates an `Access Token` and a `Refresh Token` upon successful login. The client (UI) uses these tokens to access protected resources. When the `Access Token` expires, the `Refresh Token` is used to silently obtain a new one without requiring the user to log in again.

### ✨ Highlights

* **JWT Authentication**: Secure session management using `Access Tokens` and `Refresh Tokens`.
* **Decoupled Architecture**: A separate `API` and `UI` project that can be developed and deployed independently.
* **Automatic Token Renewal**: An elegant solution using a `DelegatingHandler` in the client to automatically refresh expired access tokens.
* **ASP.NET Core Identity**: Industry-standard solution for user management.
* **Entity Framework Core**: A modern ORM for database operations.
* **Docker Support**: Includes a `docker-compose` file to easily spin up a PostgreSQL database.

## 🛠️ Tech Stack

* **.NET 8**
* **ASP.NET Core Web API** & **MVC**
* **Entity Framework Core** & **ASP.NET Core Identity**
* **PostgreSQL** & **Docker**

## 🏗️ Project Architecture

The project has two main parts: an **`Api`** project that handles authentication and serves data, and a **`UI`** project that acts as the client. The core of the architecture is the token-based communication between them.

## ⚙️ Getting Started

Follow these steps to run the project.


### Steps

1.  **Clone the Repository:**
    ```bash
    - git clone https://github.com/alperenbugaz/aspnetcoreauthkit.git
    - cd aspnetcoreauthkit
    ```

2.  **Start the Database:**
    ```bash
    - cd Api/Db
    - docker compose up -d
    ```

3.  **Run the API Project:**
    ```bash
    cd ../../Api
    dotnet ef database update
    dotnet run
    ```
    The API will run on `https://localhost:7045`.

4.  **Run the UI Project:**
    ```bash
    cd ../UI
    dotnet run
    ```
    The UI will run on `https://localhost:7285`.

5.  **Use the Application:**
    * Go to `https://localhost:7285`.
    * Log in with: **Username**: `user1`, **Password**: `123456`

---

## 👨‍💻 In-Depth Technical Breakdown

This section provides a deeper dive into the source code, explaining the configuration and startup logic for both the API and UI projects.

### 1. Configuration (`appsettings.Development.json`)

Configuration is key to the decoupled nature of this project.

#### Api/appsettings.Development.json

This file holds the settings for database connections and JWT generation.

```json
{
  "Jwt": {
    "Issuer": "https://localhost:7045", // API's address
    "Audience": "https://localhost:7285", // UI's address
    "Key": "gk2R8vZsP9nW6xTqL7uJr3HbXy9NdMfE1bVtAsCgYiXpZoKuQlWtErDcSvBhNmAx",
    "AccessTokenDurationInMinutes": 1,
    "RefreshTokenDurationInDays": 7
  },
  "ConnectionStrings": {
    "DefaultConnection": "Host=localhost;Port=5432;Database=appdb;Username=root;Password=root"
  }
}
```

- **`Jwt.Issuer`** : The authority that creates the token (the API itself).
- **`Jwt.Audience`** : The intended recipient of the token (the UI). The API will reject tokens intended for other audiences.
- **`Jwt.Key`** :  A secret key used for signing and verifying tokens to ensure they haven't been tampered with.
- **`Jwt.AccessTokenDurationInMinutes`** : The lifespan of an access token. It's kept short (1 minute in this case) for security.
- **`Jwt.RefreshTokenDurationInDays`** :  The lifespan of a refresh token. This is much longer, allowing users to stay logged in across sessions.
- **`ConnectionStrings.DefaultConnection`** :  The connection string for the our PostgreSQL database.

#### UI/appsettings.Development.json

The UI configuration is simpler, mainly defining where to find the API.


```json
{
  "ApiSettings": {
    "BaseUrl": "https://localhost:7045"
  }
}
```
- **`ApiSettings.BaseUrl`** : The root address of the API. The HttpClient in the UI project uses this to send requests.

### 1. Service and Pipeline Configuration (`Program.cs`)

This is where all services are registered and the HTTP request pipeline is assembled.


#### Api/Program.cs

The API's Program.cs configures Identity, JWT authentication, and the database context.


This file holds the settings for database connections and JWT generation.

```json
// 1. Add DB and Identity
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

// 2. Configure JWT Authentication
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = builder.Configuration["Jwt:Issuer"],
        ValidAudience = builder.Configuration["Jwt:Audience"],
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]))
    };
});

// 3. Register Custom Services
builder.Services.AddScoped<ITokenService, TokenService>();

// In the pipeline:
app.UseAuthentication();
app.UseAuthorization();
```

- **`Database & Identity`** : AddDbContext registers the EF Core context with the PostgreSQL connection string. AddIdentity sets up the core services for user and role management.
- **`JWT Authentication`** : AddAuthentication sets the default scheme to JwtBearer. AddJwtBearer configures how JWTs should be validated. It uses the Issuer, Audience, and Key from appsettings.json to ensure that incoming tokens are legitimate.
- **`Custom Services`** : ITokenService is registered with its implementation, making it available for dependency injection in controllers.

#### UI/Program.cs

```json
// 1. Configure Cookie Authentication for the UI's own session
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/Account/Login";
        options.AccessDeniedPath = "/Home/AccessDenied";
        options.ExpireTimeSpan = TimeSpan.FromDays(1);
    });

// 2. Register the automatic token refresh handler
builder.Services.AddTransient<TokenRefreshHandler>();

// 3. Configure HttpClient to communicate with the API
builder.Services.AddHttpClient("ApiClient", client =>
{
    client.BaseAddress = new Uri(builder.Configuration["ApiSettings:BaseUrl"]);
})
.AddHttpMessageHandler<TokenRefreshHandler>(); // Attach the handler to the client

// In the pipeline:
app.UseAuthentication();
app.UseAuthorization();
```

- **`Cookie Authentication`** : The UI uses cookie-based authentication to manage its own user sessions. When a user logs in, the UI creates a cookie containing the JWTs received from the API. LoginPath redirects unauthenticated users to the login page.
- **`TokenRefreshHandler`** :The custom DelegatingHandler is registered as a transient service.
- **`HttpClient Configuration`** : AddHttpClient creates a named `HttpClient`. Crucially, .`AddHttpMessageHandler<TokenRefreshHandler>()` attaches our custom handler to its request pipeline. Now, every request made by this HttpClient will pass through TokenRefreshHandler, which automatically attaches the access token and handles refreshing it if it expires.
