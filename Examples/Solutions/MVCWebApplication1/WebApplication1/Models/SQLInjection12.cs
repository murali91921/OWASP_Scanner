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
            string querystring = "Select * from Employees where Name LIKE '%@" + name + "%'";
            using (System.Data.Common.DbCommand cmd = db.GetSqlStringCommand(querystring))
            {
                cmd.CommandText = querystring;
                db.ExecuteNonQuery(cmd);
            }
            querystring = "Select * from Employees where Name LIKE '%' + @name + '%'";
            using (System.Data.Common.DbCommand cmd = db.GetSqlStringCommand(querystring))
            {
                db.AddInParameter(cmd, "@name", DbType.String, name);
                db.ExecuteNonQuery(cmd);
            }
            DataSet ds = db.ExecuteDataSet(CommandType.Text, querystring);
            db.ExecuteNonQuery(CommandType.Text, querystring);
            db.ExecuteScalar(CommandType.Text, querystring);
            db.ExecuteReader(CommandType.Text, querystring);

            DbConnection _internalConnection = db.CreateConnection();
            _internalConnection.Open();
            DbTransaction _internalTransaction = _internalConnection.BeginTransaction();

            db.ExecuteReader(_internalTransaction, CommandType.Text, querystring);
            using (System.Data.Common.DbCommand cmd = db.GetSqlStringCommand(querystring))
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