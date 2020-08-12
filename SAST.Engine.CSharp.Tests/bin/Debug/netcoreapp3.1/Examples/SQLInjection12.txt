using Microsoft.Practices.EnterpriseLibrary.Data.Sql;
using System.Data;
using System.Data.Common;

namespace WebApplication2.Models
{
    public class SQLInjection12
    {

        public void Search(string name)
        {
            SqlDatabase db = new SqlDatabase("ConnectionString");
            string queryString = "Select * from Employees where Name LIKE '%@" + name + "%'";
            using (System.Data.Common.DbCommand cmd = db.GetSqlStringCommand(queryString))
            {
                cmd.CommandText = queryString;
                db.ExecuteNonQuery(cmd);
            }
            queryString = "Select * from Employees where Name LIKE '%' + @name + '%'";
            using (System.Data.Common.DbCommand cmd = db.GetSqlStringCommand(queryString))
            {
                db.AddInParameter(cmd, "@name", DbType.String, name);
                db.ExecuteNonQuery(cmd);
            }
            DataSet ds = db.ExecuteDataSet(CommandType.Text, queryString);
            db.ExecuteNonQuery(CommandType.Text, queryString);
            db.ExecuteScalar(CommandType.Text, queryString);
            db.ExecuteReader(CommandType.Text, queryString);

            DbConnection _internalConnection = db.CreateConnection();
            _internalConnection.Open();
            DbTransaction _internalTransaction = _internalConnection.BeginTransaction();

            db.ExecuteReader(_internalTransaction, CommandType.Text, queryString);
            using (System.Data.Common.DbCommand cmd = db.GetSqlStringCommand(queryString))
            {
                db.AddInParameter(cmd, "@name", DbType.String, name);
                db.ExecuteNonQuery(cmd);
            }
        }
    }
    public class Employee
    {
        public int Id { get; set; }
        public string Name { get; set; }
    }
}