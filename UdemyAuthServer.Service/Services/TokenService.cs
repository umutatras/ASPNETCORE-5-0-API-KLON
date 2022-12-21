using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using SharedLibrary.Configuration;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using UdemyAuthServer.Core.Configuration;
using UdemyAuthServer.Core.DTOs;
using UdemyAuthServer.Core.Entities;
using UdemyAuthServer.Core.Services;

namespace UdemyAuthServer.Service.Services
{
    public class TokenService : ITokenService
    {
        private readonly UserManager<UserApp> _userManager;
        private readonly CustomTokenOptions _tokenOption;

        public TokenService(IOptions<CustomTokenOptions>options, UserManager<UserApp> userManager)
        {
            _tokenOption = options.Value;
            _userManager = userManager;
        }
        //resfresh token oluşturma ve şifreleme
        private string CreateRefreshToken()
        {
            var numberByte = new Byte[32];
            using var rnd = RandomNumberGenerator.Create();
            rnd.GetBytes(numberByte);
            return Convert.ToBase64String(numberByte);
        }
        //üyelik sistemi olanlarda token oluşturma
        private IEnumerable<Claim>GetClaims(UserApp userApp,List<string>audiences)
        {
            var userList = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier,userApp.Id),
                new Claim(JwtRegisteredClaimNames.Email,userApp.Email),
                new Claim(ClaimTypes.Name,userApp.UserName),
                new Claim(JwtRegisteredClaimNames.Jti,Guid.NewGuid().ToString())

            };
            userList.AddRange(audiences.Select(x=>new Claim(JwtRegisteredClaimNames.Aud,x)));
            return userList;

        }
        //üyelik sistemi gerektirmeyen sistemlerde token oluşturma
        private IEnumerable<Claim>GetClaimsByClient(Client client)
        {
            var claims=new List<Claim>();
            claims.AddRange(client.Audiences.Select(x => new Claim(JwtRegisteredClaimNames.Aud, x)));
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString());
            new Claim(JwtRegisteredClaimNames.Sub, client.Id.ToString());
            return claims;
        }
        public TokenDto CreateToken(UserApp userApp)
        {
            var accessTokenExpiration = DateTime.Now.AddMinutes(_tokenOption.AccesTokenExpiration);
            var refreshTokenExpiration = DateTime.Now.AddMinutes(_tokenOption.RefreshTokenExpiration);
            var securityKey=SignService.GetSymetricSecurityKey(_tokenOption.SecurityKey);
            SigningCredentials signingCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256Signature);
            JwtSecurityToken jwtSecurityToken=new JwtSecurityToken(issuer:_tokenOption.Issuer,
                expires:accessTokenExpiration,
                notBefore:DateTime.Now,
                claims:GetClaims(userApp,_tokenOption.Audience),
                signingCredentials:signingCredentials);
            var handler = new JwtSecurityTokenHandler();
            var token=handler.WriteToken(jwtSecurityToken);
            var tokenDto = new TokenDto
            {
                AccessToken= token,
                RefreshToken=CreateRefreshToken(),
                AccessTokenExpiration=accessTokenExpiration,
                RefreshTokenExpiration= refreshTokenExpiration
            };
            return tokenDto;
        }

        public ClientTokenDto CreatetokenByClient(Client client)
        {
            var accessTokenExpiration = DateTime.Now.AddMinutes(_tokenOption.AccesTokenExpiration);     
            var securityKey = SignService.GetSymetricSecurityKey(_tokenOption.SecurityKey);
            SigningCredentials signingCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256Signature);
            JwtSecurityToken jwtSecurityToken = new JwtSecurityToken(issuer: _tokenOption.Issuer,
                expires: accessTokenExpiration,
                notBefore: DateTime.Now,
                claims: GetClaimsByClient(client),
                signingCredentials: signingCredentials);
            var handler = new JwtSecurityTokenHandler();
            var token = handler.WriteToken(jwtSecurityToken);
            var tokenDto = new ClientTokenDto
            {
                AccessToken = token,              
                AccessTokenExpiration = accessTokenExpiration,
             
            };
            return tokenDto;
        }
    }
}
