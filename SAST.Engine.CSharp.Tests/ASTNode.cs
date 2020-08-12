using System;
using System.Collections.Generic;
using System.Linq;
namespace ASTTask
{
[Serializable]
    public class ASTNode
    {
        public string Name { get; }

        public IDictionary<string, string> Properties { get; }
        public IList<ASTNode> Children { get; } = new List<ASTNode>();

        public ASTNode(IDictionary<string, string> properties) =>
            (Properties, Name) = (properties, properties.Values.First());

        public void AddChild(ASTNode child)
        {
            Children.Add(child);
        }

        public override string ToString()
        {
            return Properties.Values.First();
        }
    }
}