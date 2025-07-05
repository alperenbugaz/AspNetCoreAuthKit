namespace UI.Dtos
{
    public class IndexViewDto
    {
        public string UserName { get; set; }
        public bool IsAuthenticated { get; set; }

        public List<ClaimViewDto> MvcAuthClaims { get; set; } = new();

        public string? AccessToken { get; set; }
        public string? RefreshToken { get; set; }
        public DateTime? AccessTokenExpiration { get; set; }

        public string ExpirationMessage { get; set; }

        public string? AccessTokenExpirationISO { get; set; }

    }
}
