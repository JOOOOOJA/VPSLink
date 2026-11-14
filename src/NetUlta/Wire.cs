using System.Buffers.Binary;

namespace NetUlta;

sealed class Wire
{
    public const int Max = 65535;
    public const int MaxUdp = 65507;
    readonly Stream input, output;
    readonly SemaphoreSlim gate = new(1, 1);
    public Wire(Stream input, Stream output) { this.input = input; this.output = output; }
    public static async Task ReadFull(Stream s, Memory<byte> data, CancellationToken ct)
    {
        while (!data.IsEmpty)
        {
            int n = await s.ReadAsync(data, ct);
            if (n == 0) throw new EndOfStreamException();
            data = data[n..];
        }
    }
    public async Task<(byte Type, byte[] Payload)> Read(CancellationToken ct)
    {
        var header = new byte[5];
        await ReadFull(input, header, ct);
        int size = BinaryPrimitives.ReadInt32BigEndian(header);
        if (size is < 0 or > Max) throw new IOException("Неверный размер сообщения моста.");
        var body = new byte[size];
        await ReadFull(input, body, ct);
        return (header[4], body);
    }
    public async Task Send(char type, ReadOnlyMemory<byte> data, CancellationToken ct)
    {
        if (data.Length > Max) throw new ArgumentOutOfRangeException(nameof(data));
        var frame = new byte[5 + data.Length];
        BinaryPrimitives.WriteInt32BigEndian(frame, data.Length);
        frame[4] = (byte)type;
        data.CopyTo(frame.AsMemory(5));
        await gate.WaitAsync(ct);
        try { await output.WriteAsync(frame, ct); await output.FlushAsync(ct); }
        finally { gate.Release(); }
    }
}

