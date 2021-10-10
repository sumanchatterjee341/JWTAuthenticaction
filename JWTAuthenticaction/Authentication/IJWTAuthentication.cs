using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace JWTAuthenticaction.Authentication
{
    public interface IJWTAuthentication
    {
        string GenerateToken();
        bool ValidatedToken(string incomingToken);
    }
}
