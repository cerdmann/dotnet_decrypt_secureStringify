namespace OpenSslTokenDecryptor
{
    public interface ITokenParser
    {
        string Digest { get; }
        byte[] Data { get; }
        byte[] Salt { get; }
    }
}