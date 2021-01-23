using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SAST.Engine.CSharp.Constants;
using SAST.Engine.CSharp.Contract;
using SAST.Engine.CSharp.Constants;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System.Text;

namespace SAST.Engine.CSharp.Scanners
{
    internal class CompositeFormatStringScanner : IScanner
    {
        private static readonly string[] FormatMethods =
        {
            KnownMethod.string_Format,
            KnownMethod.System_Console_Write,
            KnownMethod.System_Console_WriteLine,
            KnownMethod.System_IO_TextWriter_Write,
            KnownMethod.System_IO_TextWriter_WriteLine,
            KnownMethod.System_IO_StreamWriter_Write,
            KnownMethod.System_IO_StreamWriter_WriteLine,
            KnownMethod.System_Diagnostics_Debug_WriteLine,
            KnownMethod.System_Diagnostics_Trace_TraceError,
            KnownMethod.System_Diagnostics_Trace_TraceWarning,
            KnownMethod.System_Diagnostics_Trace_TraceInformation,
            KnownMethod.System_Diagnostics_TraceSource_TraceInformation,
            KnownMethod.System_Text_StringBuilder_AppendFormat
        };
        private static readonly int MaxValueForArgumentIndexAndAlignment = 1_000_000;

        private static readonly Regex StringFormatItemRegex = new Regex(@"^(?<Index>\d+)(\s*,\s*(?<Alignment>-?\d+)\s*)?(:(?<Format>.+))?$", RegexOptions.Compiled);

        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(SyntaxNode syntaxNode, string filePath, SemanticModel model = null, Solution solution = null)
        {
            List<VulnerabilityDetail> vulnerabilities = new List<VulnerabilityDetail>();
            var invocations = syntaxNode.DescendantNodesAndSelf().OfType<InvocationExpressionSyntax>();
            foreach (var invocation in invocations)
            {
                if (!(model.GetSymbol(invocation) is IMethodSymbol methodSymbol) ||
                    !methodSymbol.Parameters.Any() || methodSymbol.Parameters.All(x => x.Name != "format"))
                    continue;

                if (!FormatMethods.Contains(methodSymbol.ContainingType.ToString() + "." + methodSymbol.Name))
                    continue;

                var formatArgumentIndex = methodSymbol.Parameters[0].ContainingType.ToString() == KnownType.System_IFormatProvider
                    ? 1 : 0;
                var formatStringExpression = invocation.ArgumentList.Arguments[formatArgumentIndex];

                var constValue = model.GetConstantValue(formatStringExpression.Expression);
                if (!constValue.HasValue)
                    continue;

                var failure = TryParseAndValidate(constValue.Value as string, invocation.ArgumentList,
                    formatArgumentIndex, model);
                if (failure == null || CanIgnoreFailure(failure, methodSymbol.Name, invocation.ArgumentList.Arguments.Count))
                    continue;

                vulnerabilities.Add(VulnerabilityDetail.Create(filePath, invocation.Expression, Enums.ScannerType.None));
            }
            return vulnerabilities;
        }

        private static ValidationFailure TryParseAndValidate(string formatStringText, ArgumentListSyntax argumentList, int formatArgumentIndex, SemanticModel semanticModel)
            => formatStringText == null ? ValidationFailure.NullFormatString : ExtractFormatItems(formatStringText, out var formatStringItems) ??
            TryValidateFormatString(formatStringItems, argumentList, formatArgumentIndex, semanticModel);

        private static ValidationFailure TryValidateFormatString(ICollection<FormatStringItem> formatStringItems, ArgumentListSyntax argumentList, int formatArgumentIndex, SemanticModel semanticModel)
        {
            if (formatStringItems.Any(x => x.Index > MaxValueForArgumentIndexAndAlignment))
                return ValidationFailure.FormatItemIndexBiggerThanMaxValue;
            if (formatStringItems.Any(x => x.Alignment > MaxValueForArgumentIndexAndAlignment))
                return ValidationFailure.FormatItemAlignmentBiggerThanMaxValue;

            var formatArguments = argumentList.Arguments
                .Skip(formatArgumentIndex + 1).Select(arg => FormatStringArgument.Create(arg.Expression, semanticModel)).ToList();
            var maxFormatItemIndex = formatStringItems.Max(item => (int?)item.Index);

            var realArgumentsCount = formatArguments.Count;
            if (formatArguments.Count == 1 && formatArguments[0].TypeSymbol.TypeKind == TypeKind.Array)
            {
                realArgumentsCount = formatArguments[0].ArraySize;
                if (realArgumentsCount == -1)
                    // can't statically check the override that supplies args in an array variable
                    return null;
            }

            return IsSimpleString(formatStringItems.Count, realArgumentsCount) ??
                HasFormatItemIndexTooBig(maxFormatItemIndex, realArgumentsCount) ??
                HasMissingFormatItemIndex(formatStringItems, maxFormatItemIndex) ??
                HasUnusedArguments(formatArguments, maxFormatItemIndex);
        }

        private static bool CanIgnoreFailure(ValidationFailure failure, string methodName, int argumentsCount)
        {
            if (methodName.EndsWith("Format") ||
                failure == ValidationFailure.UnusedFormatArguments ||
                failure == ValidationFailure.FormatItemIndexBiggerThanArgsCount)
                return false;
            // All methods in HandledFormatMethods that do not end on Format have an overload
            // with only one argument and the rule should not raise an issue
            return argumentsCount == 1;
        }

        private static ValidationFailure HasFormatItemIndexTooBig(int? maxFormatItemIndex, int argumentsCount)
        {
            if (maxFormatItemIndex.HasValue && maxFormatItemIndex.Value + 1 > argumentsCount)
                return ValidationFailure.FormatItemIndexBiggerThanArgsCount;
            return null;
        }

        private static ValidationFailure IsSimpleString(int formatStringItemsCount, int argumentsCount)
            => formatStringItemsCount == 0 && argumentsCount == 0 ? ValidationFailure.SimpleString : null;

        private static ValidationFailure ExtractFormatItems(string formatString, out List<FormatStringItem> formatStringItems)
        {
            formatStringItems = new List<FormatStringItem>();
            var curlyBraceCount = 0;
            StringBuilder currentFormatItemBuilder = null;
            var isEscapingOpenCurlyBrace = false;
            var isEscapingCloseCurlyBrace = false;
            for (var i = 0; i < formatString.Length; i++)
            {
                var currentChar = formatString[i];
                var previousChar = i > 0 ? formatString[i - 1] : '\0';

                if (currentChar == '{')
                {
                    if (previousChar == '{' && !isEscapingOpenCurlyBrace)
                    {
                        curlyBraceCount--;
                        isEscapingOpenCurlyBrace = true;
                        currentFormatItemBuilder = null;
                        continue;
                    }

                    curlyBraceCount++;
                    isEscapingOpenCurlyBrace = false;
                    if (currentFormatItemBuilder == null)
                        currentFormatItemBuilder = new StringBuilder();
                    continue;
                }

                if (previousChar == '{' && !char.IsDigit(currentChar) && currentFormatItemBuilder != null)
                    return ValidationFailure.InvalidCharacterAfterOpenCurlyBrace;

                if (currentChar == '}')
                {
                    isEscapingCloseCurlyBrace = previousChar == '}' && !isEscapingCloseCurlyBrace;
                    curlyBraceCount = isEscapingCloseCurlyBrace
                        ? curlyBraceCount + 1
                        : curlyBraceCount - 1;

                    if (currentFormatItemBuilder != null)
                    {
                        var failure = TryParseItem(currentFormatItemBuilder.ToString(), out var formatStringItem);
                        if (failure != null)
                            return failure;

                        formatStringItems.Add(formatStringItem);
                        currentFormatItemBuilder = null;
                    }
                    continue;
                }
                currentFormatItemBuilder?.Append(currentChar);
            }

            if (curlyBraceCount != 0)
                return ValidationFailure.UnbalancedCurlyBraceCount;

            return null;
        }

        private static ValidationFailure TryParseItem(string formatItem, out FormatStringItem formatStringItem)
        {
            formatStringItem = null;

            var matchResult = StringFormatItemRegex.Match(formatItem);
            if (!matchResult.Success)
                return ValidationFailure.FormatItemMalformed;

            var index = int.Parse(matchResult.Groups["Index"].Value);
            var alignment = matchResult.Groups["Alignment"].Success ? (int?)int.Parse(matchResult.Groups["Alignment"].Value) : null;
            var formatString = matchResult.Groups["Format"].Success ? matchResult.Groups["Format"].Value : null;
            formatStringItem = new FormatStringItem(index, alignment, formatString);
            return null;
        }

        private static ValidationFailure HasMissingFormatItemIndex(IEnumerable<FormatStringItem> formatStringItems, int? maxFormatItemIndex)
        {
            if (!maxFormatItemIndex.HasValue)
                return null;

            var missingFormatItemIndexes = Enumerable.Range(0, maxFormatItemIndex.Value + 1)
                .Except(formatStringItems.Select(item => item.Index))
                .Select(i => i.ToString()).ToList();

            if (missingFormatItemIndexes.Count > 0)
            {
                var failure = ValidationFailure.MissingFormatItemIndex;
                failure.AdditionalData = missingFormatItemIndexes;
                return failure;
            }
            return null;
        }

        private static ValidationFailure HasUnusedArguments(List<FormatStringArgument> formatArguments, int? maxFormatItemIndex)
        {
            var unusedArgumentNames = formatArguments.Skip((maxFormatItemIndex ?? -1) + 1).Select(arg => arg.Name).ToList();
            if (unusedArgumentNames.Count > 0)
            {
                var failure = ValidationFailure.UnusedFormatArguments;
                failure.AdditionalData = unusedArgumentNames;
                return failure;
            }
            return null;
        }

        private sealed class FormatStringItem
        {
            public FormatStringItem(int index, int? alignment, string formatString)
            {
                Index = index;
                Alignment = alignment;
                FormatString = formatString;
            }

            public int Index { get; }
            public int? Alignment { get; }
            public string FormatString { get; }
        }

        private sealed class FormatStringArgument
        {
            public string Name { get; }
            public ITypeSymbol TypeSymbol { get; }
            public int ArraySize { get; }

            public FormatStringArgument(string name, ITypeSymbol typeSymbol, int arraySize = -1)
            {
                Name = name;
                TypeSymbol = typeSymbol;
                ArraySize = arraySize;
            }

            public static FormatStringArgument Create(ExpressionSyntax expression, SemanticModel semanticModel)
            {
                var type = semanticModel.GetTypeSymbol(expression);
                var arraySize = -1;
                if (type != null && type.TypeKind == TypeKind.Array)
                {
                    if (expression is ImplicitArrayCreationExpressionSyntax implicitArray)
                        arraySize = implicitArray.Initializer.Expressions.Count;

                    if (expression is ArrayCreationExpressionSyntax array && array.Initializer != null)
                        arraySize = array.Initializer.Expressions.Count;
                }
                return new FormatStringArgument(expression.ToString(), type, arraySize);
            }
        }

        public class ValidationFailure
        {
            public static readonly ValidationFailure NullFormatString = new ValidationFailure("Invalid string format, the format string cannot be null.");
            public static readonly ValidationFailure InvalidCharacterAfterOpenCurlyBrace = new ValidationFailure("Invalid string format, opening curly brace can only be followed by a digit or an opening curly brace.");
            public static readonly ValidationFailure UnbalancedCurlyBraceCount = new ValidationFailure("Invalid string format, unbalanced curly brace count.");
            public static readonly ValidationFailure FormatItemMalformed = new ValidationFailure("Invalid string format, all format items should comply with the following pattern '{index[,alignment][:formatString]}'.");
            public static readonly ValidationFailure FormatItemIndexBiggerThanArgsCount = new ValidationFailure("Invalid string format, the highest string format item index should not be greater than the arguments count.");
            public static readonly ValidationFailure FormatItemIndexBiggerThanMaxValue = new ValidationFailure($"Invalid string format, the string format item index should not be greater than {MaxValueForArgumentIndexAndAlignment}.");
            public static readonly ValidationFailure FormatItemAlignmentBiggerThanMaxValue = new ValidationFailure($"Invalid string format, the string format item alignment should not be greater than {MaxValueForArgumentIndexAndAlignment}.");
            public static readonly ValidationFailure SimpleString = new ValidationFailure("Remove this formatting call and simply use the input string.");
            public static readonly ValidationFailure UnknownError = new ValidationFailure("Invalid string format, the format string is invalid and is likely to throw at runtime.");
            public static readonly ValidationFailure MissingFormatItemIndex = new ValidationFailure("The format string might be wrong, the following item indexes are missing: ");
            public static readonly ValidationFailure UnusedFormatArguments = new ValidationFailure("The format string might be wrong, the following arguments are unused: ");

            private readonly string message;

            private ValidationFailure(string message) => this.message = message;

            public IEnumerable<string> AdditionalData { get; set; }

            public override string ToString() => AdditionalData == null ? message : string.Concat(message, "-----", AdditionalData);
            //: string.Concat(message, AdditionalData.ToSentence(quoteWords: true), ".");
        }
    }
}