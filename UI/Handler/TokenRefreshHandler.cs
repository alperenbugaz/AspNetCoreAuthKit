using System.Net.Http.Headers;
using System.Net;
using System.Text.Json;
using System.Text;

namespace UI.Handler
{
    public class TokenRefreshHandler : DelegatingHandler
    {
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly IConfiguration _configuration;
        private static readonly SemaphoreSlim _semaphore = new(1, 1);

        public TokenRefreshHandler(IHttpContextAccessor httpContextAccessor, IHttpClientFactory httpClientFactory, IConfiguration configuration)
        {
            _httpContextAccessor = httpContextAccessor;
            _httpClientFactory = httpClientFactory;
            _configuration = configuration;
        }
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var context = _httpContextAccessor.HttpContext;
            var accessToken = context.Request.Cookies["accessToken"];

            if (!string.IsNullOrEmpty(accessToken))
            {
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
            }

            var response = await base.SendAsync(request, cancellationToken);

            if (response.StatusCode == HttpStatusCode.Unauthorized)
            {
                await _semaphore.WaitAsync(cancellationToken); // Aynı anda tek bir yenileme işlemi yap
                try
                {
                    // Tekrar kontrol et, başka bir thread token'ı yenilemiş olabilir
                    var newAccessToken = context.Request.Cookies["accessToken"];
                    if (newAccessToken != accessToken)
                    {
                        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", newAccessToken);
                        response = await base.SendAsync(request, cancellationToken); // İsteği yeniden gönder
                    }
                    else
                    {
                        var refreshToken = context.Request.Cookies["refreshToken"];
                        if (string.IsNullOrEmpty(refreshToken))
                        {
                            // Refresh token yoksa logout yap
                            context.Response.Redirect("/Account/Logout");
                            return response;
                        }

                        var newTokens = await RefreshTokensAsync(refreshToken, cancellationToken);
                        if (newTokens == null)
                        {
                            // Yenileme başarısızsa logout yap
                            context.Response.Redirect("/Account/Logout");
                            return response;
                        }

                        // Yeni token'ları cookie'ye yaz
                        SetTokenCookies(context, newTokens.AccessToken, newTokens.RefreshToken);

                        // Orijinal isteği yeni token ile tekrar gönder
                        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", newTokens.AccessToken);
                        response = await base.SendAsync(request.Clone(), cancellationToken);
                    }
                }
                finally
                {
                    _semaphore.Release();
                }
            }

            return response;
        }

        private async Task<TokenResponse?> RefreshTokensAsync(string refreshToken, CancellationToken cancellationToken)
        {
            var apiClient = _httpClientFactory.CreateClient("ApiClient_NoHandler"); // Handler'sız bir client
            var apiBaseUrl = _configuration["ApiSettings:BaseUrl"];

            var requestBody = new { accessToken = "dummy", refreshToken }; // Access token'ı boş gönderebiliriz, API tarafı kullanmıyor
            var content = new StringContent(JsonSerializer.Serialize(requestBody), Encoding.UTF8, "application/json");

            var response = await apiClient.PostAsync($"{apiBaseUrl}/api/auth/refresh-token", content, cancellationToken);

            if (response.IsSuccessStatusCode)
            {
                var tokenString = await response.Content.ReadAsStringAsync(cancellationToken);
                return JsonSerializer.Deserialize<TokenResponse>(tokenString, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            }
            return null;
        }

        private void SetTokenCookies(HttpContext context, string accessToken, string refreshToken)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Secure = true, // Production'da her zaman true olmalı
                SameSite = SameSiteMode.Strict
            };
            context.Response.Cookies.Append("accessToken", accessToken, cookieOptions);
            context.Response.Cookies.Append("refreshToken", refreshToken, cookieOptions);
        }

        private class TokenResponse { public string AccessToken { get; set; } public string RefreshToken { get; set; } }
    }

    // HttpRequestMessage'ı klonlamak için bir extension method
    public static class HttpRequestMessageExtensions
    {
        public static HttpRequestMessage Clone(this HttpRequestMessage req)
        {
            var clone = new HttpRequestMessage(req.Method, req.RequestUri)
            {
                Content = req.Content,
                Version = req.Version
            };
            foreach (KeyValuePair<string, IEnumerable<string>> header in req.Headers)
            {
                clone.Headers.TryAddWithoutValidation(header.Key, header.Value);
            }
            return clone;
        }
    }
}
