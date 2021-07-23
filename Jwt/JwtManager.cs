using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace MTH.Security.Jwt
{
    public class JwtManager
    {

        private string _key = string.Empty;
        private string _iss = string.Empty;
        private int _expiryInMin = 20;

        public JwtManager()
        {

        }

        public JwtManager(string key, string iss, int expiryInMin)
        {
            _key = key;
            _iss = iss;
            _expiryInMin = expiryInMin;
        }

        public string GenerateJwtToken(Dictionary<string, string> claims)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(_key));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256Signature);

            var permClaims = new List<Claim>();
            foreach (var claim in claims)
            {
                if (claim.Key.ToLower() != ".issued" && claim.Key.ToLower() != ".expires")
                    permClaims.Add(new Claim(claim.Key, claim.Value));
            }

            var token = new JwtSecurityToken(
                            issuer: _iss, //Issure    
                            audience: _iss,  //Audience    
                            claims: permClaims,
                            notBefore: DateTime.Now,
                            expires: DateTime.Now.AddMinutes(_expiryInMin),
                            signingCredentials: credentials);
            var jwt_token = new JwtSecurityTokenHandler().WriteToken(token);
            return $"Bearer {jwt_token}";
        }
    }
}
