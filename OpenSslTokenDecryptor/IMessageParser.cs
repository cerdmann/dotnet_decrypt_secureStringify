namespace OpenSslTokenDecryptor
{
    public interface IMessageParser
    {
        string Nonce { get; }
        string Message { get; }
    }
}