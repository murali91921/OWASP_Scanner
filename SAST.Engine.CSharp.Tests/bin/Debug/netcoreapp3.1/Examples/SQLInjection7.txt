using System.Web;
using System.Web.UI.WebControls;

namespace WebApplication1.Models
{
    public class UISqlExample7
    {
        const string connectionstring = "Data Source=(local);Initial Catalog=Northwind;Integrated Security=true;";
        const string provider = "SqlProvider";
        const string dataFilePath = "D:\\Access.mdb";
        public void Run(string empName)
        {
            string queryString = "SELECT * FROM Employee where Name = " + empName;
            System.Web.UI.WebControls.AccessDataSource accessData = new System.Web.UI.WebControls.AccessDataSource();
            accessData = new AccessDataSource(dataFilePath, queryString);
            System.Web.UI.WebControls.SqlDataSource sqlData = new System.Web.UI.WebControls.SqlDataSource();
            sqlData = new System.Web.UI.WebControls.SqlDataSource(connectionstring, queryString);
            sqlData = new System.Web.UI.WebControls.SqlDataSource(provider, connectionstring, queryString);
            sqlData = new System.Web.UI.WebControls.SqlDataSource(selectCommand: queryString, connectionString: connectionstring);
            sqlData = new System.Web.UI.WebControls.SqlDataSource(providerName: provider, selectCommand: queryString, connectionString: connectionstring);
            sqlData.SelectCommand = queryString;
            sqlData.UpdateCommand = queryString;
            sqlData.InsertCommand = queryString;
            sqlData.DeleteCommand = queryString;
        }
    }
}