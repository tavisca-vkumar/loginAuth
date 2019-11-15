using LoginWithAuthKey.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JWTAuthentication.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class LoginController : Controller
    {
        private IConfiguration _config;
        private UserManager<UserModel> _userManager;

        public LoginController(IConfiguration config)
        {
            _config = config;
        }
        
        [AllowAnonymous]
        [HttpPost]
        public IActionResult Login([FromBody]LoginModel login)
        {
            IActionResult response = Unauthorized();
            var user = AuthenticateUser(login);

            if (user != null)
            {
                var tokenString = GenerateJSONWebToken(user);
                response = Ok(new { token = tokenString });
            }

            return response;

        }
        private string GenerateJSONWebToken(UserModel userInfo)
        {
            
            IdentityOptions _options = new IdentityOptions();
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                   {
                        new Claim("UserID",userInfo.Id.ToString()),
                        //new Claim("UserName ",userInfo.usernamme),
                        //new Claim("password",userInfo.Password)

                   }),
                Expires = DateTime.UtcNow.AddDays(1),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"])), SecurityAlgorithms.HmacSha256Signature)
            };
            var tokenHandler = new JwtSecurityTokenHandler();
            var securityToken = tokenHandler.CreateToken(tokenDescriptor);
            var token = tokenHandler.WriteToken(securityToken);
            return token;

            /*  var token = new JwtSecurityToken(_config["Jwt:Issuer"],
                _config["Jwt:Issuer"],
                null,
                expires: DateTime.Now.AddMinutes(120),
                signingCredentials: credentials);

              return new JwtSecurityTokenHandler().WriteToken(token);*/
        }

        private UserModel AuthenticateUser(LoginModel login)
        {
            UserModel user = null;

            //Validate the User Credentials  
            //Demo Purpose, I have Passed HardCoded User Information  
            if (login.UserName == "vikesh" && login.Password == "vikesh")
            {
                user = new UserModel()
                {
                    usernamme = "vikesh",
                    Password = "vikesh"
                   
                };
            }
            return user;
        }
        [HttpGet]
        [Authorize(Roles = "Admin")]
        [Route("Value")]
        public ActionResult<IEnumerable<string>> GetValue()
        {
            return new string[] { "value1", "value2", "value3", "value4", "value5" };
        }

    }
}