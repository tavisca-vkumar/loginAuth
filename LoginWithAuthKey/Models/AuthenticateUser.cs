using JWTAuthentication.Controllers;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace LoginWithAuthKey.Models
{
    
        public class AuthenticateUser : IdentityDbContext
    {
        public AuthenticateUser(DbContextOptions options) : base(options)
        {
            ApplicationUsers.Add(new UserModel(){UserName = "vikesh",
                Password = "vikesh"
                });
            ApplicationUsers.Add(new UserModel()
            {
                UserName = "paresh",
                Password = "paresh"
                
            });
        }

        public DbSet<UserModel> ApplicationUsers { get; set; }
        
    }
}
