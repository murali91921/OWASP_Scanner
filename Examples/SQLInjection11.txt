using Microsoft.EntityFrameworkCore;
using Microsoft.Data.SqlClient;
using System.Linq;
using System;

using System.Runtime;
using Microsoft.EntityFrameworkCore.Relational;

namespace WebApplication1.Models
{
    public class SQLInjection11
    {
        public void Search(string name)
        {
            string querystring = "Update Employees set SearchCount = SearchCount+1 where Name LIKE '%" + name + "%'";
            using (var ctx = new EmployeeDB())
            {
                var student = ctx.Employees
                                .FromSqlRaw(querystring);
            }
            // FormattableString querystring1 = $"Select * from Employees where Name LIKE '%{name}%'";
            // using (var ctx = new EmployeeDB())
            // {
            //     var student = ctx.Employees
            //                     .FromSqlInterpolated(querystring1)
            //                     .FirstOrDefault();
            //     student = ctx.Employees
            //                     .FromSqlInterpolated($"Select * from Employees where Name LIKE '%{name}%'")
            //                     .FirstOrDefault();
            // }
            querystring = "Update Employees set SearchCount = SearchCount+1 where Name LIKE '%" + name + "%'";
            using (var ctx = new EmployeeDB())
            {
                int noOfRowUpdated = ctx.Database.ExecuteSqlCommand(querystring);
                noOfRowUpdated = ctx.Database.ExecuteSqlCommand(querystring, new SqlParameter("@name", name));
                noOfRowUpdated = ctx.Database.ExecuteSqlCommandAsync(querystring).Result;
                noOfRowUpdated = ctx.Database.ExecuteSqlCommandAsync(querystring, new SqlParameter("@name", name)).Result;
                noOfRowUpdated = ctx.Database.ExecuteSqlRaw(querystring);
                noOfRowUpdated = ctx.Database.ExecuteSqlRaw(querystring, new SqlParameter("@name", name));
                noOfRowUpdated = ctx.Database.ExecuteSqlRawAsync(querystring).Result;
                noOfRowUpdated = ctx.Database.ExecuteSqlRawAsync(querystring, new SqlParameter("@name", name)).Result;
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