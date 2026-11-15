using System.Buffers.Binary;
using System.IO.Pipes;
using NetUlta;

static class SshOutputTests
{
    public static async Task Run()
    {
        int plain = await Burst(false), buffered = await Burst(true);
        if (buffered >= plain / 4) throw new Exception($"Pipe reads not coalesced: {plain} -> {buffered}");
        Console.WriteLine($"PASS: SSH output burst preserves frames with {plain} -> {buffered} pipe reads");
        using var input = new AnonymousPipeServerStream(PipeDirection.In, HandleInheritability.None, 65536);
        using var output = new AnonymousPipeClientStream(PipeDirection.Out, input.ClientSafePipeHandle);
        var wire = new Wire(SshSession.BufferOutput(input), Stream.Null);
        var frame = Frame(17);
        // A partial header, followed by the remainder, must work while the writer
        // stays open. Buffering must not wait for 64 KiB or EOF to release a packet.
        output.Write(frame, 0, 2);
        var pending = wire.Read(CancellationToken.None);
        await Task.Delay(30);
        if (pending.IsCompleted) throw new Exception("Incomplete header accepted");
        output.Write(frame, 2, frame.Length - 2);
        var result = await pending.WaitAsync(TimeSpan.FromSeconds(3));
        Verify(result, 17);
        Console.WriteLine("PASS: SSH output releases sparse fragmented frame without waiting for buffer fill or EOF");
    }
    static byte[] Frame(int i)
    {
        var data = new byte[1405];
        BinaryPrimitives.WriteInt32BigEndian(data, 1400); data[4] = (byte)'D';
        data.AsSpan(5).Fill((byte)i);
        BinaryPrimitives.WriteInt32BigEndian(data.AsSpan(5), i);
        return data;
    }
    static void Verify((byte Type, byte[] Payload) frame, int i)
    {
        if (frame.Type != 'D' || frame.Payload.Length != 1400 ||
            BinaryPrimitives.ReadInt32BigEndian(frame.Payload) != i ||
            frame.Payload.AsSpan(4).ToArray().Any(b => b != (byte)i)) throw new Exception("Pipe frame corruption");
    }
    static async Task<int> Burst(bool buffered)
    {
        using var input = new AnonymousPipeServerStream(PipeDirection.In, HandleInheritability.None, 65536);
        using var output = new AnonymousPipeClientStream(PipeDirection.Out, input.ClientSafePipeHandle);
        var counter = new CountReads(input);
        var wire = new Wire(buffered ? SshSession.BufferOutput(counter) : counter, Stream.Null);
        var bytes = Enumerable.Range(0, 1000).SelectMany(Frame).ToArray();
        var writer = Task.Run(() => output.Write(bytes));
        for (int i = 0; i < 1000; i++) Verify(await wire.Read(CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(10)), i);
        await writer;
        return counter.Reads;
    }
    sealed class CountReads : Stream
    {
        readonly Stream inner;
        public CountReads(Stream inner) => this.inner = inner;
        public int Reads;
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override int Read(byte[] b, int o, int n) { Reads++; return inner.Read(b,o,n); }
        public override ValueTask<int> ReadAsync(Memory<byte> b, CancellationToken ct=default) { Reads++; return inner.ReadAsync(b,ct); }
        public override Task<int> ReadAsync(byte[] b,int o,int n,CancellationToken ct) { Reads++; return inner.ReadAsync(b,o,n,ct); }
        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long o,SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] b,int o,int n) => throw new NotSupportedException();
    }
}
