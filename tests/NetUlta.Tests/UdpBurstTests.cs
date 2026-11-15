using System.Net;
using System.Net.Sockets;
using NetUlta;

static class UdpBurstTests
{
    public static async Task Run()
    {
        using var receiver = new LocalUdp(0);
        using var sender = new UdpClient();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var endpoint = new IPEndPoint(IPAddress.Loopback, receiver.Port);
        // Reproduce a video-frame burst arriving while SSH cannot immediately
        // drain UDP. No reader runs until the whole bounded burst has arrived.
        for (int n = 0; n < 64; n++)
        {
            var data = new byte[1400];
            BitConverter.TryWriteBytes(data.AsSpan(), n);
            await sender.SendAsync(data, endpoint, timeout.Token);
        }
        for (int n = 0; n < 64; n++)
        {
            var packet = await receiver.Client.ReceiveAsync(timeout.Token);
            if (packet.Buffer.Length != 1400 || BitConverter.ToInt32(packet.Buffer) != n)
                throw new Exception("UDP burst lost or reordered a packet");
        }
        Console.WriteLine("PASS: UDP receives a 64-packet video burst while the reader is paused");
    }
}
