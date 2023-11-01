using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace BlazorAuth.Controllers
{
    public class AuthController : Controller
    {
        [HttpGet("/auth/login")]
        [AllowAnonymous]
        public async Task<IActionResult> LogInUser(string u, string p)
        {
            var cookieAndAuthTicketExpiryDT = DateTimeOffset.UtcNow.AddSeconds(30);

            var identity = new ClaimsIdentity(CookieAuthenticationDefaults.AuthenticationScheme);
            identity.AddClaim(new Claim(ClaimTypes.Sid, "555"));
            identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, "Id"));
            identity.AddClaim(new Claim(ClaimTypes.Name, "Test"));
            identity.AddClaim(new Claim(ClaimTypes.Role, "Admin"));
            identity.AddClaim(new Claim(ClaimTypes.Expiration, cookieAndAuthTicketExpiryDT.ToString()));

            var cClaims = new ClaimsPrincipal(identity); ;

            await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme,
                cClaims,
                new AuthenticationProperties { 
                    IsPersistent = true,
                    IssuedUtc = DateTimeOffset.UtcNow,
                    ExpiresUtc = cookieAndAuthTicketExpiryDT
                });

            return Redirect("/securedpage");

        }

        [HttpGet("/auth/logout")]
        [AllowAnonymous]
        public async Task<IActionResult> LogOutUser()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

            return Redirect("/");
        }
    }
}
