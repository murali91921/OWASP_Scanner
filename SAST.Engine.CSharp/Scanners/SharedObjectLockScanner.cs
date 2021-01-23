using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.CSharp;
using SAST.Engine.CSharp.Contract;
using SAST.Engine.CSharp.Constants;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SAST.Engine.CSharp.Scanners
{
    internal class SharedObjectLockScanner : IScanner
    {
        private static readonly string[] WeakTypes = {
            KnownType.System_ExecutionEngineException,
            KnownType.System_OutOfMemoryException,
            KnownType.System_StackOverflowException
        };
        private static readonly string[] InheritWeakTypes = {
            KnownType.System_Threading_Thread,
            KnownType.System_MarshalByRefObject,
            KnownType.System_Reflection_MemberInfo,
            KnownType.System_Reflection_ParameterInfo
        };

        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(SyntaxNode syntaxNode, string filePath, SemanticModel model = null, Solution solution = null)
        {
            List<VulnerabilityDetail> vulnerabilities = new List<VulnerabilityDetail>();
            var lockStatements = syntaxNode.DescendantNodesAndSelf().OfType<LockStatementSyntax>();

            foreach (var item in lockStatements)
                if (IsWeakIdentity(item.Expression, model))
                    vulnerabilities.Add(VulnerabilityDetail.Create(filePath, item.Expression, Enums.ScannerType.SharedObjectLock));

            var invocations = syntaxNode.DescendantNodesAndSelf().OfType<InvocationExpressionSyntax>();
            foreach (var item in invocations)
            {
                var methodName = item.Expression.GetName();
                if ((methodName != "Enter" && methodName != "TryEnter") || item.ArgumentList.Arguments.Count == 0)
                    continue;

                if (!(model.GetSymbol(item) is IMethodSymbol method) || method.ContainingType.ToString() != KnownType.System_Threading_Monitor)
                    continue;

                if (IsWeakIdentity(item.ArgumentList.Arguments[0].Expression, model))
                    vulnerabilities.Add(VulnerabilityDetail.Create(filePath, item.ArgumentList.Arguments[0].Expression, Enums.ScannerType.SharedObjectLock));
            }
            return vulnerabilities;
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