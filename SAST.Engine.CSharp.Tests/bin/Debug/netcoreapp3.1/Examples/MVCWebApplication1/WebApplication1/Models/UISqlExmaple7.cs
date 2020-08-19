using System.Web;
using System.Web.UI.WebControls;

namespace WebApplication1.Models
{
    public class UISqlExmaple7
    {
        const string connectionstring = "Data Source=(local);Initial Catalog=Northwind;Integrated Security=true;";
        const string provider = "SqlProvider";
        const string dataFilePath = "D:\\Access.mdb";
        public void Run(string empName)
        {
            string queryString = "SELECT * FROM Employee where Name = " + empName;
            System.Web.UI.WebControls.SqlDataSource sqlData = new System.Web.UI.WebControls.SqlDataSource();
            System.Web.UI.WebControls.SqlDataSourceView sqlDataView = new System.Web.UI.WebControls.SqlDataSourceView(sqlData, "View", HttpContext.Current);
            sqlData = new System.Web.UI.WebControls.SqlDataSource(connectionstring, queryString);
            sqlData = new System.Web.UI.WebControls.SqlDataSource(provider, connectionstring, queryString);
            sqlData = new System.Web.UI.WebControls.SqlDataSource(selectCommand: queryString, connectionString: connectionstring);
            sqlData = new System.Web.UI.WebControls.SqlDataSource(providerName: provider, selectCommand: queryString, connectionString: connectionstring);
            sqlDataView.SelectCommand = queryString;
            sqlDataView.UpdateCommand = queryString;
            sqlDataView.InsertCommand = queryString;
            sqlDataView.DeleteCommand = queryString;
        }
    }
}