namespace OpenSslTokenDecryptor
{
    public interface IKeyGenerator
    {
        byte[] Key { get; }
        byte[] Iv { get; }
    }
}