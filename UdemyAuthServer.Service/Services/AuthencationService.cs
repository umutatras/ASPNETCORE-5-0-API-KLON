using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using SharedLibrary.Dtos;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using UdemyAuthServer.Core.Configuration;
using UdemyAuthServer.Core.DTOs;
using UdemyAuthServer.Core.Entities;
using UdemyAuthServer.Core.Repositories;
using UdemyAuthServer.Core.Services;
using UdemyAuthServer.Core.UnitOfWork;

namespace UdemyAuthServer.Service.Services
{
    public class AuthencationService : IAuthenticationService
    {
        private readonly List<Client> _clients;
        private readonly ITokenService _tokenService;
        private readonly UserManager<UserApp> _userManager;
        private readonly IUnitOFWork _unitOFWork;
        private readonly IGenericRepository<UserRefreshToken> _userRefreshTokenService;
        public AuthencationService(IOptions<List<Client>> optionsClient, ITokenService tokenService, UserManager<UserApp> userManager, IUnitOFWork unitOFWork, IGenericRepository<UserRefreshToken> userRefreshTokenService)
        {
            _clients = optionsClient.Value;
            _tokenService = tokenService;
            _userManager = userManager;
            _unitOFWork = unitOFWork;
            _userRefreshTokenService = userRefreshTokenService;
        }     

        public async Task<Response<TokenDto>> CreateTokenAsync(LoginDto loginDto)
        {
            if(loginDto==null)throw new ArgumentNullException(nameof(loginDto));

            var user =await _userManager.FindByEmailAsync(loginDto.Email);

            if (user == null) return Response<TokenDto>.Fail("Email Veya Passwaord Yanlış",400,true);

            if(!await _userManager.CheckPasswordAsync(user,loginDto.Password))
            {
                return Response<TokenDto>.Fail("Email Veya Passwaord Yanlış", 400, true);
            }

            var token = _tokenService.CreateToken(user);
            var userResfreshToken = await _userRefreshTokenService.Where(x => x.UserId == user.Id).SingleOrDefaultAsync();
            if(userResfreshToken==null)
            {
                await _userRefreshTokenService.AddAsync(new UserRefreshToken
                {
                    UserId = user.Id,
                    Code = token.RefreshToken,
                    Expiration = token.RefreshTokenExpiration
                });
            }
            else
            {
                userResfreshToken.Code = token.RefreshToken;
                userResfreshToken.Expiration=token.RefreshTokenExpiration;
            }
            await _unitOFWork.SaveChangesAsync();
            return Response<TokenDto>.Success(token, 200);

        }

        public Response<ClientTokenDto> CreateTokenByClient(ClientLoginDto clientLoginDto)
        {
            var client = _clients.SingleOrDefault(x => x.Id == clientLoginDto.ClientId && x.Secret == clientLoginDto.ClientSecret);

            if (client == null)
            {
                return Response<ClientTokenDto>.Fail("ClientId or ClientSecret not found", 404, true);
            }

            var token = _tokenService.CreatetokenByClient(client);

            return Response<ClientTokenDto>.Success(token, 200);
        }

        public async Task<Response<TokenDto>> CreateTokenByRefreshToken(string refreshToken)
        {
           var existRefreshToken=await _userRefreshTokenService.Where(x=>x.Code== refreshToken).SingleOrDefaultAsync();
            if(existRefreshToken==null)
            {
                return Response<TokenDto>.Fail("Refresh token not found", 404, true);
            }
            var user = await _userManager.FindByIdAsync(existRefreshToken.UserId);
            if(user == null) {
                return Response<TokenDto>.Fail("UserId  not found", 404, true);
            }
            var token=_tokenService.CreateToken(user);

            existRefreshToken.Code = token.RefreshToken;
            existRefreshToken.Expiration = token.RefreshTokenExpiration;

            await _unitOFWork.SaveChangesAsync();
            return Response<TokenDto>.Success(token, 200);

        }

        public async Task<Response<NoDataDto>> RevokeRefreshToken(string refreshToken)
        {
            var existRefreshToken = await _userRefreshTokenService.Where(x => x.Code == refreshToken).SingleOrDefaultAsync();
            if (existRefreshToken == null)
            {
                return Response<NoDataDto>.Fail("Refresh token not found",404,true);    
            }
            _userRefreshTokenService.Remove(existRefreshToken);
            await _unitOFWork.SaveChangesAsync();
            return Response<NoDataDto>.Success(200);
            
        }
    }
}
