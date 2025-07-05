using Api.Db;
using Api.Entities;
using Api.Services.TokenService;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);
var configuration = builder.Configuration;

builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection")));
builder.Services.AddControllers();
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true, // Yay�mc�y� do�rula
        ValidateAudience = true, // Hedefi do�rula
        ValidateLifetime = true, // Token'�n �mr�n� kontrol et
        ValidateIssuerSigningKey = true, // �mza anahtar�n� do�rula
        ValidIssuer = configuration["Jwt:Issuer"],
        ValidAudience = configuration["Jwt:Audience"],
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["Jwt:Key"])),
        ClockSkew = TimeSpan.Zero // S�re tolerans�n� s�f�rla
    };
});


builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    options.Password.RequireDigit = true; 
    options.Password.RequiredLength = 6; 
    options.Password.RequireNonAlphanumeric = false; 
    options.Password.RequireUppercase = false; 
    options.Password.RequireLowercase = false; 
})
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders();



builder.Services.AddScoped<ITokenService, TokenService>();


builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();


try
{
    // Servisler i�in bir scope olu�turuyoruz.
    using (var scope = app.Services.CreateScope())
    {
        var serviceProvider = scope.ServiceProvider;
        // SeedData.Initialize metodumuzu �a��r�yoruz.
        await Api.Db.SeedData.Initialize(serviceProvider);
    }
}
catch (Exception ex)
{
    // Tohumlama s�ras�nda bir hata olursa log'layal�m.
    var logger = app.Services.GetRequiredService<ILogger<Program>>();
    logger.LogError(ex, "An error occurred during seeding the database.");
}

app.Run();
