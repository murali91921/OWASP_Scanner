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
    public class SqlInjectionScanner : IScanner
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
                ITypeSymbol typeSymbol = model.GetTypeInfo(objectCreation).Type as ITypeSymbol;
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
                    if (model.GetTypeInfo(argument.Expression).Type.ToString() == "string" || model.GetTypeInfo(argument.Expression).Type.ToString() == "System.String")
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
                SymbolInfo symbolInfo = model.GetSymbolInfo(method);
                IMethodSymbol symbol = null;
                if (symbolInfo.Symbol != null)
                    symbol = symbolInfo.Symbol as IMethodSymbol;
                else if (symbolInfo.CandidateSymbols.Count() > 0)
                    symbol = symbolInfo.CandidateSymbols.First() as IMethodSymbol;
                if (symbol == null)
                    continue;
                if (!CommandExecuteMethods.Any(obj => obj == symbol.ReceiverType.OriginalDefinition.ToString() + "." + symbol.Name.ToString()))
                    continue;
                foreach (var argument in method.ArgumentList.Arguments)
                {
                    ITypeSymbol typeSymbol = model.GetTypeInfo(argument.Expression).Type;
                    if (typeSymbol.ToString() == "string" || typeSymbol.ToString() == "System.String")
                    {
                        if (argument.NameColon == null || CommandExecuteParameters.Any(param => param == argument.NameColon.Name.ToString()))
                        {
                            lstVulnerableCheck.Add(argument.Expression);
                            break;
                        }
                    }
                }
            }
            var assignments = syntaxNode.DescendantNodes().OfType<AssignmentExpressionSyntax>().Where(
                obj => !obj.Right.IsKind(SyntaxKind.ObjectCreationExpression)).ToList();
            foreach (var item in assignments)
            {
                IPropertySymbol symbol = model.GetSymbolInfo(item.Left).Symbol as IPropertySymbol;
                if (symbol == null)
                    continue;
                if (CommandTextProperties.Any(obj => obj == symbol.ToString()))
                    lstVulnerableCheck.Add((item as AssignmentExpressionSyntax).Right);
            }
            foreach (var item in lstVulnerableCheck)
            {
                if (IsVulnerable(item))
                    lstVulnerableStatements.Add(item.Parent);
            }
            return Map.ConvertToVulnerabilityList(filePath, lstVulnerableStatements, ScannerType.SqlInjection);
        }
        private bool IsVulnerable(SyntaxNode node, ISymbol callingSymbol = null)
        {
            if (node is IdentifierNameSyntax)
            {
                ITypeSymbol type = model.GetTypeInfo(node).Type;
                if (type.ToString() != "string" || type.ToString() != "System.String")
                    return false;

                bool vulnerable = false;
                ISymbol symbol = model.GetSymbolInfo(node).Symbol;
                if (symbol == null || symbol.Equals(callingSymbol, SymbolEqualityComparer.Default))
                    return false;

                var references = SymbolFinder.FindReferencesAsync(symbol, solution).Result;
                foreach (var reference in references)
                {
                    var currentNode = syntaxNode.FindNode(reference.Definition.Locations.First().SourceSpan);
                    vulnerable = IsVulnerable(currentNode);
                    foreach (var refLocation in reference.Locations)
                    {
                        currentNode = syntaxNode.FindNode(refLocation.Location.SourceSpan);
                        if (currentNode.SpanStart < node.SpanStart && Utils.CheckSameMethod(currentNode, node))
                        {
                            var assignment = currentNode.Ancestors().OfType<AssignmentExpressionSyntax>().FirstOrDefault();
                            if (assignment == null)
                                continue;
                            if (currentNode.SpanStart < assignment.Right.SpanStart)
                                vulnerable = IsVulnerable(assignment.Right, symbol);
                        }
                    }
                }
                return vulnerable;
            }
            else if (node is BinaryExpressionSyntax)
            {
                var left = IsVulnerable((node as BinaryExpressionSyntax).Left, callingSymbol);
                var right = IsVulnerable((node as BinaryExpressionSyntax).Right, callingSymbol);
                return left || right;
            }
            else if (node is VariableDeclaratorSyntax && (node as VariableDeclaratorSyntax).Initializer != null)
                return IsVulnerable((node as VariableDeclaratorSyntax).Initializer.Value);
            else if (node is AssignmentExpressionSyntax)
                return IsVulnerable((node as AssignmentExpressionSyntax).Right);
            else if (node is InterpolatedStringExpressionSyntax)
            {
                bool vulnerable = false;
                var contents = (node as InterpolatedStringExpressionSyntax).Contents.OfType<InterpolationSyntax>();
                foreach (var item in contents)
                    vulnerable = vulnerable || IsVulnerable(item.Expression, callingSymbol);
                return vulnerable;
            }
            else if (node is ParameterSyntax)
                return true;
            else
                return false;
        }
    }
}