using NetUlta;
sealed class DelayedGatewayTransport : ITransport
{
    public int Attempts;
    public string Name => "cold-start fixture";
    public Task<Stream> Connect(string host, int port, CancellationToken ct)
    {
        if (++Attempts == 1) throw new OperationCanceledException("fixture cold start");
        return new TcpTransport().Connect(host, port, ct);
    }
}
