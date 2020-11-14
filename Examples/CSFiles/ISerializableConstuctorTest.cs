//Example from Rolsyn Analysers
//CA2237
//CA2229
//CA2116 AllowPartiallyTrustedCallersAttribute
using System;
using System.Runtime.Serialization;

[Serializable]
public class CA2229NoConstructor : ISerializable			//NonComplaint
{
	public void GetObjectData(SerializationInfo info, StreamingContext context)
	{
		throw new NotImplementedException();
	}
}

[Serializable]
internal class CA2229NoConstructorInternal : ISerializable	//Complaint
{
	public void GetObjectData(SerializationInfo info, StreamingContext context)
	{
		throw new NotImplementedException();
	}
}

[Serializable]
public class CA2229HasConstructor : ISerializable
{
	protected CA2229HasConstructor(SerializationInfo info, StreamingContext context) { }	//Complaint

	public void GetObjectData(SerializationInfo info, StreamingContext context)
	{
		throw new NotImplementedException();
	}
}

[Serializable]
public sealed class CA2229HasConstructor1 : ISerializable
{
	private CA2229HasConstructor1(SerializationInfo info, StreamingContext context) { }	//Complaint

	public void GetObjectData(SerializationInfo info, StreamingContext context)
	{
		throw new NotImplementedException();
	}
}

[Serializable]
public class CA2229HasConstructorWrongAccessibility : ISerializable
{
	public CA2229HasConstructorWrongAccessibility(SerializationInfo info, StreamingContext context) { }	// NonComplaint

	public void GetObjectData(SerializationInfo info, StreamingContext context)
	{
		throw new NotImplementedException();
	}
}

[Serializable]
public class CA2229HasConstructorWrongAccessibility1 : ISerializable
{
	internal CA2229HasConstructorWrongAccessibility1(SerializationInfo info, StreamingContext context) { }	//NonComplaint

	public void GetObjectData(SerializationInfo info, StreamingContext context)
	{
		throw new NotImplementedException();
	}
}

[Serializable]
public sealed class CA2229HasConstructorWrongAccessibility2 : ISerializable
{
	protected internal CA2229HasConstructorWrongAccessibility2(SerializationInfo info, StreamingContext context) { }	//NonComplaint

	public void GetObjectData(SerializationInfo info, StreamingContext context)
	{
		throw new NotImplementedException();
	}
}

[Serializable]
public class CA2229HasConstructorWrongAccessibility3 : ISerializable
{
	protected internal CA2229HasConstructorWrongAccessibility3(SerializationInfo info, StreamingContext context) { }	//NonComplaint

	public void GetObjectData(SerializationInfo info, StreamingContext context)
	{
		throw new NotImplementedException();
	}
}

[Serializable]
public class CA2229HasConstructorWrongOrder : ISerializable
{
	protected CA2229HasConstructorWrongOrder(StreamingContext context, SerializationInfo info) { }	//NonComplaint

	public void GetObjectData(SerializationInfo info, StreamingContext context)
	{
		throw new NotImplementedException();
	}
}

[Serializable]
public class CA2229SerializableProper : ISerializable	//NonComplaint
{
	public void GetObjectData(SerializationInfo info, StreamingContext context)
	{
		throw new NotImplementedException();
	}
}

class A
{
    [Serializable]
    public delegate void B();
}
public interface I : ISerializable
{
    string Name { get; }
}
//To fix a violation of this rule, implement the serialization constructor.
//For a sealed class, make the constructor private; otherwise, make it protected.
