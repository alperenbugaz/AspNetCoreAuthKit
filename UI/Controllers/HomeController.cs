using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.IdentityModel.Tokens.Jwt;
using UI.Dtos;
using UI.Models;

namespace UI.Controllers
{
    [Authorize]

    public class HomeController : Controller
    {
        private readonly IHttpClientFactory _httpClientFactory;

        public HomeController(IHttpClientFactory httpClientFactory)
        {
            _httpClientFactory = httpClientFactory;
        }


        public IActionResult Index()
        {
            var viewModel = new IndexViewDto();

            if (User.Identity is { IsAuthenticated: true })
            {
                viewModel.IsAuthenticated = true;
                viewModel.UserName = User.Identity.Name;
                viewModel.MvcAuthClaims = User.Claims.Select(c => new ClaimViewDto { Type = c.Type, Value = c.Value }).ToList();
            }

            viewModel.AccessToken = Request.Cookies["accessToken"];
            viewModel.RefreshToken = Request.Cookies["refreshToken"];

            if (!string.IsNullOrEmpty(viewModel.AccessToken))
            {
                var handler = new JwtSecurityTokenHandler();
                try
                {
                    var token = handler.ReadJwtToken(viewModel.AccessToken);
                    viewModel.AccessTokenExpiration = token.ValidTo; 
                    viewModel.AccessTokenExpirationISO = viewModel.AccessTokenExpiration.Value.ToString("o");

                    var timeUntilExpiration = viewModel.AccessTokenExpiration.Value - DateTime.UtcNow;

                    if (timeUntilExpiration.TotalSeconds < 0)
                    {
                        viewModel.ExpirationMessage = $"Access Token'ýn süresi {timeUntilExpiration.TotalSeconds:N0} saniye önce doldu! Bir sonraki API isteðinde yenilenecek.";
                    }
                    else
                    {
                        viewModel.ExpirationMessage = $"Access Token'ýn süresinin dolmasýna: {timeUntilExpiration.Minutes} dakika, {timeUntilExpiration.Seconds} saniye kaldý.";
                    }
                }
                catch (Exception)
                {
                    viewModel.ExpirationMessage = "Access Token okunamadý veya geçersiz formatta.";
                }
            }

            return View(viewModel);
        }
    }
}
