using Api.Entities;
using Microsoft.AspNetCore.Identity;

namespace Api.Db
{
    public static class SeedData
    {
        // IServiceProvider aracılığıyla gerekli servisleri alarak asenkron bir şekilde tohumlama yapıyoruz.
        public static async Task Initialize(IServiceProvider serviceProvider)
        {
            var userManager = serviceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var roleManager = serviceProvider.GetRequiredService<RoleManager<IdentityRole>>();

            await SeedRolesAsync(roleManager);
            await SeedUsersAsync(userManager);
        }

        // Başlangıç Rollerimizi oluşturuyoruz.
        private static async Task SeedRolesAsync(RoleManager<IdentityRole> roleManager)
        {
            string[] roleNames = { "Admin", "User" };

            foreach (var roleName in roleNames)
            {
                // Rol daha önce oluşturulmamışsa oluştur.
                var roleExist = await roleManager.RoleExistsAsync(roleName);
                if (!roleExist)
                {
                    await roleManager.CreateAsync(new IdentityRole(roleName));
                }
            }
        }

        // Başlangıç Kullanıcılarımızı oluşturuyoruz.
        private static async Task SeedUsersAsync(UserManager<ApplicationUser> userManager)
        {
            // user1 (Admin)
            if (await userManager.FindByNameAsync("user1") == null)
            {
                var user = new ApplicationUser
                {
                    UserName = "user1",
                    Email = "user1@example.com",
                    EmailConfirmed = true // Seed edilen kullanıcıların mailini onaylı kabul edelim.
                };

                var result = await userManager.CreateAsync(user, "123456");

                if (result.Succeeded)
                {
                    await userManager.AddToRoleAsync(user, "Admin");
                }
            }

            // user2 (User)
            if (await userManager.FindByNameAsync("user2") == null)
            {
                var user = new ApplicationUser
                {
                    UserName = "user2",
                    Email = "user2@example.com",
                    EmailConfirmed = true
                };

                var result = await userManager.CreateAsync(user, "123456");

                if (result.Succeeded)
                {
                    await userManager.AddToRoleAsync(user, "User");
                }
            }

            // user3 (User)
            if (await userManager.FindByNameAsync("user3") == null)
            {
                var user = new ApplicationUser
                {
                    UserName = "user3",
                    Email = "user3@example.com",
                    EmailConfirmed = true
                };

                var result = await userManager.CreateAsync(user, "123456");

                if (result.Succeeded)
                {
                    await userManager.AddToRoleAsync(user, "User");
                }
            }
        }
    }
}