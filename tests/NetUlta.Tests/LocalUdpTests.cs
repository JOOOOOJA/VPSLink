using System.Net;
using System.Net.Sockets;
using NetUlta;

static class LocalUdpTests
{
    public static async Task Run()
    {
        using var local = new LocalUdp(0);
        using var wrong = new UdpClient(new IPEndPoint(IPAddress.Parse("127.0.0.2"),0));
        using var right = new UdpClient(new IPEndPoint(IPAddress.Loopback,0));
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        var destination = new IPEndPoint(IPAddress.Loopback,local.Port);
        await wrong.SendAsync(new byte[]{9},destination,stop.Token);
        await right.SendAsync(new byte[]{1,2,3},destination,stop.Token);
        var result = await local.ReceiveAsync(stop.Token);
        if (!result.Buffer.SequenceEqual(new byte[]{1,2,3}) || !result.RemoteEndPoint.Equals(right.Client.LocalEndPoint))
            throw new Exception("Foreign UDP source accepted");
        await local.Client.SendAsync(result.Buffer,result.RemoteEndPoint,stop.Token);
        if (!(await right.ReceiveAsync(stop.Token)).Buffer.SequenceEqual(result.Buffer))
            throw new Exception("UDP response changed");
        if (!LocalUdpAddress.Resolve("").Equals(IPAddress.Loopback)) throw new Exception("Legacy profiles changed");
        try { LocalUdpAddress.Resolve("missing-adapter-for-test"); throw new Exception("Missing adapter silently fell back"); }
        catch (UserFault) { }
        Console.WriteLine("PASS: local UDP rejects other sources, preserves replies, and fails closed for a missing adapter");
    }
}
