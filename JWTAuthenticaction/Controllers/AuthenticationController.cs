using JWTAuthenticaction.Authentication;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace JWTAuthenticaction.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AuthenticationController : Controller
    {
        private readonly IJWTAuthentication _jWTAuthentication;
        public AuthenticationController(IJWTAuthentication jWTAuthentication)
        {
            _jWTAuthentication = jWTAuthentication;
        }
        
        [HttpPost]
        public string GenerateJWTToken()
        {
            return _jWTAuthentication.GenerateToken();
        }
    }
}
