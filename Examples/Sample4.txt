using System;
using System.IO;
using System.Linq;
namespace Sample2
{
    struct Point
    {
        private int _innerX;
        private int _innerY;

        public int X 
        {
            get 
            {
                return _innerX;
            }

            set 
            {
                _innerX = value;
                PointChanged(_innerX);
            }
        }

        public int Y
        {
            get
            {
                return _innerY;
            }
            set
        }
        public event Action<int> PointChanged;
        public void getValues(int paramX, int paramY)
        {
            _innerX=paramX;
            _innerY=paramY;
        }
    }
}