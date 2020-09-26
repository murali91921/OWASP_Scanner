using SAST.Engine.CSharp.Enums;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.FlowAnalysis;
using Microsoft.CodeAnalysis.FindSymbols;
using Microsoft.CodeAnalysis.Text;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using System.Collections.Generic;
using SAST.Engine.CSharp.Contract;
using static System.Console;
using SAST.Engine.CSharp.Mapper;

namespace SAST.Engine.CSharp.Scanners
{
    internal class SqlInjectionScanner : IScanner
    {
        SemanticModel model;
        Solution solution;
        SyntaxNode syntaxNode;

        private static string[] CommandClasses = {
            "System.Data.Common.DbCommand",
            "System.Data.IDbCommand",
            "System.Data.SqlClient.SqlCommand",
            "System.Data.OleDb.OleDbCommand",
            "System.Data.Odbc.OdbcCommand",
            "System.Data.OracleClient.OracleCommand",
            "System.Data.SQLite.SQLiteCommand",
            "System.Data.SqlClient.SqlDataAdapter",
            "System.Data.IDbDataAdapter",
            "System.Data.OleDb.OleDbDataAdapter",
            "System.Data.Odbc.OdbcDataAdapter",
            "System.Data.OracleClient.OracleDataAdapter",
            "System.Data.SQLite.SQLiteDataAdapter",
            "System.Web.UI.WebControls.SqlDataSource",
            };

        private static string[] SqlDataSourceClass = { "System.Web.UI.WebControls.SqlDataSource" };

        private static string[] CommandTextParameters = {
            "CommandText",
            "selectCommandText",
            "cmdText",
            "selectCommand"
            };

        private static string[] CommandExecuteMethods = {
            "System.Data.Linq.DataContext.ExecuteCommand",
            "System.Data.Linq.DataContext.ExecuteQuery",
            "System.Data.SQLite.SQLiteCommand.Execute",
            "System.Data.Entity.Database.ExecuteSqlCommand",
            "System.Data.Entity.Database.ExecuteSqlCommandAsync",
            "System.Data.Entity.Database.SqlQuery",
            "System.Data.Entity.DbSet<TEntity>.SqlQuery",
            "Microsoft.EntityFrameworkCore.DbSet<TEntity>.FromSqlRaw",
            "Microsoft.EntityFrameworkCore.Infrastructure.DatabaseFacade.ExecuteSqlCommand",
            "Microsoft.EntityFrameworkCore.Infrastructure.DatabaseFacade.ExecuteSqlCommandAsync",
            "Microsoft.EntityFrameworkCore.Infrastructure.DatabaseFacade.ExecuteSqlRaw",
            "Microsoft.EntityFrameworkCore.Infrastructure.DatabaseFacade.ExecuteSqlRawAsync",
            "Microsoft.Practices.EnterpriseLibrary.Data.Database.GetSqlStringCommand",
            "Microsoft.Practices.EnterpriseLibrary.Data.Database.ExecuteScalar",
            "Microsoft.Practices.EnterpriseLibrary.Data.Database.ExecuteReader",
            "Microsoft.Practices.EnterpriseLibrary.Data.Database.ExecuteNonQuery",
            "Microsoft.Practices.EnterpriseLibrary.Data.Database.ExecuteDataSet",
        };

        private static string[] CommandExecuteParameters = {
            "query",
            "command",
            "commandText"
        };

        private static string[] CommandTextProperties = {
            "System.Data.Common.DbCommand.CommandText",
            "System.Data.IDbCommand.CommandText",
            "System.Data.SqlClient.SqlCommand.CommandText",
            "System.Data.OleDb.OleDbCommand.CommandText",
            "System.Data.Odbc.OdbcCommand.CommandText",
            "System.Data.OracleClient.OracleCommand.CommandText",
            "System.Data.SQLite.SQLiteCommand.CommandText",
            "System.Web.UI.WebControls.SqlDataSource.SelectCommand",
            "System.Web.UI.WebControls.SqlDataSource.InsertCommand",
            "System.Web.UI.WebControls.SqlDataSource.UpdateCommand",
            "System.Web.UI.WebControls.SqlDataSource.DeleteCommand",
            "System.Web.UI.WebControls.SqlDataSourceView.SelectCommand",
            "System.Web.UI.WebControls.SqlDataSourceView.InsertCommand",
            "System.Web.UI.WebControls.SqlDataSourceView.UpdateCommand",
            "System.Web.UI.WebControls.SqlDataSourceView.DeleteCommand"
        };

        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(SyntaxNode syntaxNode, string filePath, SemanticModel model = null, Solution solution = null)
        {
            this.model = model;
            this.syntaxNode = syntaxNode;
            this.solution = solution;
            List<SyntaxNode> lstVulnerableStatements = new List<SyntaxNode>();
            HashSet<SyntaxNode> lstVulnerableCheck = new HashSet<SyntaxNode>();
            var objectCreationExpressions = syntaxNode.DescendantNodes().OfType<ObjectCreationExpressionSyntax>();
            foreach (var objectCreation in objectCreationExpressions)
            {
                ITypeSymbol typeSymbol = model.GetTypeSymbol(objectCreation);
                if (typeSymbol == null)
                    continue;
                if (!Utils.DerivesFromAny(typeSymbol, CommandClasses))
                    continue;
                if (objectCreation.ArgumentList != null && objectCreation.ArgumentList.Arguments.Count > 0)
                {
                    var argument = objectCreation.ArgumentList.Arguments.First();
                    if (Utils.DerivesFromAny(typeSymbol, SqlDataSourceClass) && argument.NameColon == null)
                        argument = objectCreation.ArgumentList.Arguments.Last();

                    if (argument.NameColon != null)
                        foreach (var item in objectCreation.ArgumentList.Arguments)
                            if (CommandTextParameters.Any(text => text == item.NameColon.Name.ToString()))
                            {
                                argument = item;
                                break;
                            }
                    if (model.GetTypeSymbol(argument.Expression).SpecialType == SpecialType.System_String)
                        lstVulnerableCheck.Add(argument.Expression);
                }
                if (objectCreation.Initializer != null)
                {
                    var commandTextInitializer = objectCreation.Initializer.Expressions.OfType<AssignmentExpressionSyntax>().FirstOrDefault(
                        obj => (obj.Left as IdentifierNameSyntax).Identifier.ValueText == "CommandText");
                    if (commandTextInitializer != null)
                        lstVulnerableCheck.Add(commandTextInitializer.Right);
                }
            }
            var methods = syntaxNode.DescendantNodes().OfType<InvocationExpressionSyntax>();
            foreach (var method in methods)
            {
                IMethodSymbol symbol = model.GetSymbol(method) as IMethodSymbol;
                if (symbol == null)
                    continue;

                if (!CommandExecuteMethods.Any(obj => obj == symbol.ReceiverType.OriginalDefinition.ToString() + "." + symbol.Name.ToString()))
                    continue;

                foreach (var argument in method.ArgumentList.Arguments)
                {
                    ITypeSymbol typeSymbol = model.GetTypeSymbol(argument.Expression);
                    if (typeSymbol.SpecialType != SpecialType.System_String)
                        continue;
                    if (argument.NameColon == null || CommandExecuteParameters.Any(param => param == argument.NameColon.Name.ToString()))
                    {
                        lstVulnerableCheck.Add(argument.Expression);
                        break;
                    }
                }
            }
            var assignments = syntaxNode.DescendantNodes().OfType<AssignmentExpressionSyntax>().Where(
                obj => !obj.Right.IsKind(SyntaxKind.ObjectCreationExpression)).ToList();
            foreach (var item in assignments)
            {
                IPropertySymbol symbol = model.GetSymbol(item.Left) as IPropertySymbol;

                if (symbol == null)
                    continue;

                if (CommandTextProperties.Any(obj => obj == symbol.ToString()))
                    lstVulnerableCheck.Add((item as AssignmentExpressionSyntax).Right);
            }
            foreach (var item in lstVulnerableCheck)
            {
                if (Utils.IsVulnerable(item, model, solution))
                    lstVulnerableStatements.Add(item.Parent);
            }
            return Map.ConvertToVulnerabilityList(filePath, lstVulnerableStatements, ScannerType.SqlInjection);
        }
    }
}