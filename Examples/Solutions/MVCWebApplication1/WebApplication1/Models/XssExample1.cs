using System.Data;
using System.Data.Common;
using System.Data.Linq;
namespace VulnerableApp
{
    public class LinqExample6
    {
        public static int Run(DataContext ctx, string city)
        {
            string queryString = "SELECT * FROM dbo.Users WHERE City = '" + city + "'";
            var users = ctx.ExecuteQuery<UserEntity>(queryString);
            var users1 = ctx.ExecuteQuery(typeof(UserEntity), queryString);
            var users2 = ctx.ExecuteQuery(elementType: typeof(UserEntity), parameters: city, query: queryString);
            var users3 = ctx.ExecuteQuery(typeof(string), queryString);
            var users4 = ctx.ExecuteQuery(typeof(string), queryString, city);
            var users5 = ctx.ExecuteCommand(queryString, city);
            return 0;
        }
    }
    class UserEntity
    {
    }
}