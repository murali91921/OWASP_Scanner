using System.Data.Entity;
using System.Data.SqlClient;
using System.Linq;

namespace WebApplication1.Models
{
    public class SQLInjection10
    {
        public void Search(string name)
        {
            string querystring = "Select * from Employees where Name LIKE '%@name%'";
            using (var ctx = new EmployeeDB())
            {
                var student = ctx.Employees
                                .SqlQuery(querystring, new SqlParameter("@name", name))
                                .FirstOrDefault();
            }
            querystring = "Select * from Employees where Name LIKE '%" + name + "%'";
            using (var ctx = new EmployeeDB())
            {
                var student = ctx.Employees
                                .SqlQuery(querystring)
                                .FirstOrDefault();
            }
            using (var ctx = new EmployeeDB())
            {
                string studentName = ctx.Database.SqlQuery<string>(querystring)
                                        .FirstOrDefault();
            }
            querystring = "Update Employees set SearchCount = SearchCount+1 where Name LIKE '%" + name + "%'";
            using (var ctx = new EmployeeDB())
            {
                int noOfRowUpdated = ctx.Database.ExecuteSqlCommand(querystring);
                noOfRowUpdated = ctx.Database.ExecuteSqlCommandAsync(querystring).Result;
            }
            querystring = "Update Employees set SearchCount = SearchCount+1 where Name LIKE '%@name%'";
            using (var ctx = new EmployeeDB())
            {
                int noOfRowUpdated = ctx.Database.ExecuteSqlCommand(querystring, new SqlParameter("@name", name));
                noOfRowUpdated = ctx.Database.ExecuteSqlCommandAsync(TransactionalBehavior.DoNotEnsureTransaction,querystring, new SqlParameter("@name", name)).Result;
            }
        }
    }
    public class EmployeeDB : DbContext
    {
        public virtual DbSet<Employee> Employees { set; get; }
    }
    public class Employee
    {
        public int Id { get; set; }
        public string Name { get; set; }
    }
}