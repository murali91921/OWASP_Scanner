using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.CSharp.Formatting;
using System.Collections.Generic;
using System.Linq;
using System.Diagnostics;
using System;
using System.Threading;

namespace ASTTask
{
    internal class EmptyCatch:IDisposable
    {
        public void Dispose()
        {
            GC.SuppressFinalize(this);
        }

        public List<SyntaxNode> FindEmptyCatch(SyntaxNode rootNode)
        {
            var allCatchStatements = rootNode.DescendantNodes().OfType<CatchClauseSyntax>();
            var emptyCatchNodes = new List<SyntaxNode>();
            Stopwatch watch = Stopwatch.StartNew();
            IEnumerator<CatchClauseSyntax> enumerator = allCatchStatements.GetEnumerator();
            //new Thread(() =>
            //{
                while (enumerator.MoveNext())
                {
                    var catchBlock = enumerator.Current.DescendantNodes().OfType<BlockSyntax>().First();
                    if (catchBlock.DescendantNodes().Count() == 0)
                        emptyCatchNodes.Add(enumerator.Current);
                    //Console.WriteLine("Thread end" + catchBlock.Span);
                }
            //}).Start();
            watch.Stop();
            Console.WriteLine(watch.ElapsedMilliseconds);
            return emptyCatchNodes;
        }
    }
}