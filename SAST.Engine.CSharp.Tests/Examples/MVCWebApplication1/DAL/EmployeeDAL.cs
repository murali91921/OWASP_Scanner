using System;
using System.Collections.Generic;
using System.Data.Common;
using System.Data.SqlClient;
using System.Text;

namespace DAL
{
    public class EmployeeDAL
    {
        public static string GetEmployeeDesignation(int Id)
        {
            string ret = "";
            string connectionString = "";
            SqlConnection sqlConnection = new SqlConnection(connectionString);
            SqlCommand command = new SqlCommand("SELECT Name FROM Employee where Id=" + Id, sqlConnection);
            DbDataReader dbDataReader = command.ExecuteReader();
            if (dbDataReader.Read())
                ret = dbDataReader.GetString(0);
            else
            {
                command = new SqlCommand("SELECT Name FROM Employee where Id=" + Id, sqlConnection);
                var scalar = command.ExecuteScalar();
                if (scalar != DBNull.Value)
                    ret = Convert.ToString(scalar);
            }
            return ret;
        }
        public static string GetEmployeeDesignation(string name)
        {
            string connectionString = "";
            SqlConnection sqlConnection = new SqlConnection(connectionString);
            SqlCommand command = new SqlCommand("SELECT Name FROM Employee where Name = " + name, sqlConnection);
            DbDataReader dbDataReader = command.ExecuteReader();
            string ret = ""; //dbDataReader.GetString(0);
            object scalar = command.ExecuteScalar();
            ret = scalar.ToString();
            //    ret = Convert.ToString(scalar);
            //}
            return ret;
        }
    }
}