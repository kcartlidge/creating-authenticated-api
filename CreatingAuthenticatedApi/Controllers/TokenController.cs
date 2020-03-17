using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace CreatingAuthenticatedApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class TokenController : ControllerBase
    {
        private readonly IConfiguration configuration;

        public TokenController(IConfiguration configuration)
        {
            this.configuration = configuration;
        }

        [HttpPost]
        public string GetToken([FromBody]string subject)
        {
            var now = DateTime.UtcNow;
            var seconds = int.Parse(configuration["JWT:LifetimeSeconds"]);
            var exp = now.AddSeconds(seconds);
            var key = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(configuration["JWT:Key"]));
            var iss = configuration["JWT:Issuer"];
            var aud = configuration["JWT:Audience"];
            var tokenHandler = new JwtSecurityTokenHandler();
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                    new Claim(JwtRegisteredClaimNames.Sub, subject),
                    new Claim(ClaimTypes.Role, "user"),
                }),
                IssuedAt = now,
                NotBefore = now,
                Expires = exp,
                Issuer = iss,
                Audience = aud,
                SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }
    }
}