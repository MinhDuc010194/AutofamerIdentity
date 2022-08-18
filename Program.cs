using Identity;
using Identity.Model;
using Identity.Services;
using IdentityMongo.Models;
using IdentityMongo.Settings;
using IdentityServer4.AspNetIdentity;
using IdentityServer4.Services;
using IdentityServer4.Validation;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using Server.Identity.Repository;

var builder = WebApplication.CreateBuilder(args);
ConfigurationManager configuration = builder.Configuration; // allows both to access and to set up the config
builder.Services.AddHttpContextAccessor();
IWebHostEnvironment environment = builder.Environment;

var hostIP = Utils.GetLocalIPAddress();
//string authServer = $"http://{hostIP}:2222";
string authServer = "http://127.0.0.1:10000";

//http://10.8.0.8:10099

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, options =>
    {
        options.Authority = authServer;
        options.RequireHttpsMetadata = false;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateAudience = false,
            ValidateIssuer = false
        };
    });
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy(
        "DeviceTokenRequire", policy =>
        policy.Requirements.Add(
              new DeviceTokenRequirement()));
});

var mongoDbSettings = configuration.GetSection(nameof(MongoDbConfig)).Get<MongoDbConfig>();

builder.Services.AddIdentity<ApplicationUser, ApplicationRole>().AddRoles<ApplicationRole>()
    .AddMongoDbStores<ApplicationUser, ApplicationRole, Guid>
    (
        mongoDbSettings.ConnectionString, mongoDbSettings.DatabaseName
    );
builder.Services.AddTransient<IResourceOwnerPasswordValidator, ResourceOwnerPasswordValidator<ApplicationUser>>().AddTransient<IProfileService, ProfileService>();
builder.Services.AddSingleton<IAuthorizationHandler, DeviceTokenRequirementHandler>();

//builder.Services.AddTransient<IProfileService, ProfileService>(); 

builder.Services.AddIdentityServer(options =>
{
    options.Events.RaiseSuccessEvents = true;
    options.Events.RaiseFailureEvents = true;
    options.Events.RaiseErrorEvents = true;
})
                    .AddInMemoryClients(IdentityConfiguration.Clients)
                    .AddAspNetIdentity<ApplicationUser>()
                    .AddInMemoryIdentityResources(IdentityConfiguration.IdentityResources)
                    .AddInMemoryApiScopes(IdentityConfiguration.ApiScopes)
                    .AddDeveloperSigningCredential()
                    .AddProfileService<ProfileService>();
builder.Services.AddMemoryCache();
var app = builder.Build();


// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
    Console.WriteLine("test");
}

app.Urls.Add("http://0.0.0.0:10000");
app.UseRouting();
app.UseIdentityServer();

app.UseAuthentication();
app.UseAuthorization();

app.UseExceptionHandler(a => a.Run(async context =>
{
    var exceptionHandlerPathFeature = context.Features.Get<IExceptionHandlerPathFeature>();
    var exception = exceptionHandlerPathFeature.Error;

    await context.Response.WriteAsJsonAsync(new { error = exception.Message });
}));
app.UseExceptionHandler("/error");

app.MapControllers();

app.Run();
