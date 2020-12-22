using System;
using System.Threading;

public class LockTest1
{
    public void Test()
    {
        object o = new object();
        lock (o) //Complaint
        {
            Console.WriteLine();
        }
    }
}

public class LockTest2
{
    public void Test()
    {
        string s1 = "";
        lock (s1) { }				//NonComplaint
        
		lock ("Hello") { }			//NonComplaint
        
		var o1 = new OutOfMemoryException();
        lock (o1) { }				//NonComplaint
        
		var o2 = new StackOverflowException();
        lock (o2) { }				//NonComplaint
        
		var o3 = new ExecutionEngineException();
        lock (o3) { }				//NonComplaint
        
		lock (System.Threading.Thread.CurrentThread) { } //NonComplaint
        
		lock (typeof(LockTest2)) { }	//NonComplaint
        
		System.Reflection.MemberInfo mi = null;
        lock (mi) { }				//NonComplaint
        
		System.Reflection.ConstructorInfo ci = null;
        lock (ci) { }				//NonComplaint
        
		System.Reflection.ParameterInfo pi = null;
        lock (pi) { }				//NonComplaint
        
		int[] values = { 1, 2, 3 };
        lock (values) { }			//NonComplaint
        
		System.Reflection.MemberInfo[] values1 = null;
        lock (values1) { }
        
		lock (this) { }				//NonComplaint
    }
}
public class LockTest3
{
    public void SomeMethod()
    {
        Monitor.Enter(this);		//NonComplaint
        Monitor.Enter("test1");		//NonComplaint
        bool b = true;
        Monitor.Enter(this, ref b);		//NonComplaint
        Monitor.Enter("test1", ref b);	//NonComplaint
    }
}

public class LockTest4
{
    public void SomeMethod()
    {
        Monitor.TryEnter(this);			//NonComplaint
        Monitor.TryEnter("test1");		//NonComplaint
        Monitor.TryEnter(this, 42);		//NonComplaint
        Monitor.TryEnter("test1", 42);	//NonComplaint
        Monitor.TryEnter(this, TimeSpan.FromMilliseconds(42));		//NonComplaint
        Monitor.TryEnter("test1", TimeSpan.FromMilliseconds(42));	//NonComplaint
        bool b = true;
        Monitor.TryEnter(this, ref b);			//NonComplaint
        Monitor.TryEnter("test1", ref b);		//NonComplaint
        Monitor.TryEnter(this, 42, ref b);		//NonComplaint
        Monitor.TryEnter("test1", 42, ref b);	//NonComplaint
    }
}