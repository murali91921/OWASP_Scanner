using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.CSharp;
using SAST.Engine.CSharp.Contract;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SAST.Engine.CSharp.Scanners
{
    internal class SharedObjectLockScanner : IScanner
    {
        private static readonly string Monitor_type = "System.Threading.Monitor";
        private static readonly string[] WeakTypes = {
            "System.ExecutionEngineException",
            "System.OutOfMemoryException",
            "System.StackOverflowException"
        };
        private static readonly string[] InheritWeakTypes = {
            "System.Threading.Thread",
            "System.MarshalByRefObject",
            "System.Reflection.MemberInfo",
            "System.Reflection.ParameterInfo",
        };

        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(SyntaxNode syntaxNode, string filePath, SemanticModel model = null, Solution solution = null)
        {
            List<SyntaxNode> syntaxNodes = new List<SyntaxNode>();
            var lockStatements = syntaxNode.DescendantNodesAndSelf().OfType<LockStatementSyntax>();

            foreach (var item in lockStatements)
                if (IsWeakIdentity(item.Expression, model))
                    syntaxNodes.Add(item.Expression);

            var invocations = syntaxNode.DescendantNodesAndSelf().OfType<InvocationExpressionSyntax>();
            foreach (var item in invocations)
            {
                var methodName = item.Expression.GetName();
                if ((methodName != "Enter" && methodName != "TryEnter") || item.ArgumentList.Arguments.Count == 0)
                    continue;

                IMethodSymbol method = model.GetSymbol(item) as IMethodSymbol;
                if (method == null || method.ContainingType.ToString() != Monitor_type)
                    continue;

                if (IsWeakIdentity(item.ArgumentList.Arguments[0].Expression, model))
                    syntaxNodes.Add(item.ArgumentList.Arguments[0].Expression);
            }
            return Mapper.Map.ConvertToVulnerabilityList(filePath, syntaxNodes, Enums.ScannerType.SharedObjectLock);
        }

        private static bool IsWeakIdentity(ExpressionSyntax expression, SemanticModel model)
        {
            if (expression.IsKind(SyntaxKind.ThisExpression))
                return true;

            ITypeSymbol type = model.GetTypeSymbol(expression);
            if (type == null)
                return false;

            return TypeHasWeakIdentity(type);
        }

        private static bool TypeHasWeakIdentity(ITypeSymbol type)
        {
            switch (type.TypeKind)
            {
                case TypeKind.Array:
                    return type is IArrayTypeSymbol arrayType && arrayType.ElementType.IsPrimitiveType();
                case TypeKind.Class:
                case TypeKind.TypeParameter:
                    return
                        type.SpecialType == SpecialType.System_String ||
                        WeakTypes.Contains(type.ToString()) ||
                        Utils.DerivesFromAny(type, InheritWeakTypes);
                default:
                    return false;
            }
        }
    }
}