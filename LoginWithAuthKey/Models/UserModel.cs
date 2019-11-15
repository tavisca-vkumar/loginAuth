using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations.Schema;

namespace JWTAuthentication.Controllers
{
    public class UserModel:IdentityUser
    {
        [Column(TypeName = "nvarchar(150)")]
       // public string FullName { get; set; }
        public string Password { get; set; }
        public string usernamme { get; set; }

    }
}