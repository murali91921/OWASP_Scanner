using System;
using System.IO;

namespace EmptyTryExample1
{
    class EmptyExample1
    {
        public void Snippet1()
        {
            try
            {
                Console.WriteLine("Console");
            }
            catch(Exception ex)
            {
            }
        }

        public void Snippet2()
        {
            try
            {
                try
                {
                    //Console.WriteLine("try");
                }
                catch(Exception ex)
                {
                    //Console.WriteLine("Items");
                }
            }
            catch(Exception ex)
            {
            }
        }
    }
}