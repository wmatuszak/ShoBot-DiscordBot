using System;
using System.IO;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Discord;
using Discord.WebSocket;


namespace ShoBot_DiscordBot
{
    class Program
    {
        const int TIMEOUTSEC = 5;
        const int STATETHRESHOLD = 2;

        private DiscordSocketClient _client;
        private IConfigurationRoot configuration;
        private SocketTextChannel notification;
        private string token;

        public static void Main(string[] args)
            => new Program().MainAsync().GetAwaiter().GetResult();

        public async Task MainAsync()
        {
            var builder = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("appsettings.json", optional: true, reloadOnChange: true);

            configuration = builder.Build();

            notification = null;

            _client = new DiscordSocketClient();

            _client.Log += Log;
            _client.MessageReceived += MessageReceived;

            token = configuration["Discord:BotToken"]; 
            await _client.LoginAsync(TokenType.Bot, token);
            await _client.StartAsync();
            
            await Monitor();

            // Block this task until the program is closed.
            await Task.Delay(-1);
        }

        private async Task MessageReceived(SocketMessage message)
        {
            if (message.Content == "!status")
            {
                string msg = "```diff\n";
                foreach (IConfigurationSection s in configuration.GetSection("PhatAC:Servers").GetChildren())
                {

                    if (s["Status"] == "Up")
                        msg += ("+[ONLINE] " + s["Name"] + "\n");
                    else
                        msg += ("-[OFFLINE] " + s["Name"] + "\n");
                }
                msg += "```\n";

                await message.Channel.SendMessageAsync(msg);
            }
            else if(message.Content == "!beerme")
            {
                await message.Channel.SendMessageAsync(":beer:");
            }
        }

        private Task Log(LogMessage msg)
        {
            Console.WriteLine(msg.ToString());
            return Task.CompletedTask;
        }

        private async Task Monitor()
        {
            while (true)
            {
                if (notification == null)
                {
                    foreach (SocketGuild g in _client.Guilds)
                    {
                        SocketTextChannel c = g.GetTextChannel(ulong.Parse(configuration["Discord:BotChannel"]));
                        if (c != null)
                            notification = c;
                    }
                }
                else
                {
                    if (_client.ConnectionState != ConnectionState.Connected)
                    {
                        await _client.StopAsync();
                        await _client.LogoutAsync();
                        await _client.LoginAsync(TokenType.Bot, token);
                        await _client.StartAsync();
                    }
                }

                foreach (IConfigurationSection s in configuration.GetSection("PhatAC:Servers").GetChildren())
                {
                    bool status = await IsUdpServerUp(s["Hostname"],Int32.Parse(s["Port"]));

                    if (status)
                    {
                        if (s["Status"] == "Down")
                        {
                            if (Int32.Parse(s["StatusCounter"]) < STATETHRESHOLD)
                            {
                                s["StatusCounter"] = (Int32.Parse(s["StatusCounter"]) + 1).ToString();
                            }
                            else
                            {
                                Console.WriteLine("[ALERT] Server has come online: " + s["Name"]);
                                if (notification != null)
                                    await notification.SendMessageAsync("```diff\n+[ALERT] Server has come online: " + s["Name"] + "\n```\n");
                                s["Status"] = "Up";
                                s["StatusCounter"] = "0";
                            }
                        }
                        else
                        {
                            s["StatusCounter"] = "0";
                        }
                    }
                    else
                    {

                        if (s["Status"] == "Up")
                        {
                            if (Int32.Parse(s["StatusCounter"]) < STATETHRESHOLD)
                            {
                                s["StatusCounter"] = (Int32.Parse(s["StatusCounter"]) + 1).ToString();
                            }
                            else
                            {

                                Console.WriteLine("[ALERT] Server has gone offline: " + s["Name"]);
                                if (notification != null)
                                    await notification.SendMessageAsync("```diff\n-[ALERT] Server has gone offline: " + s["Name"] + "\n```\n");
                                s["Status"] = "Down";
                                s["StatusCounter"] = "0";
                            }
                        }
                        else
                        {
                            s["StatusCounter"] = "0";
                        }
                    }

                }

                Thread.Sleep(Int32.Parse(configuration["PhatAC:RefreshRate"]));
            }
        }

        #region ThwargLauncher Server Monitor Code

        //
        // IsUdpServerUp() 
        // Author: Thwargle 
        // Source Project: https://github.com/Thwargle/ThwargLauncher
        //
        // I did not write this. Thwargle is the man! 
        //

        private async Task<bool> IsUdpServerUp(string address, int port)
        {
            UdpClient udpClient = new UdpClient();
            try
            {
                // udpClient.Client.ReceiveTimeout not used in Async calls
                udpClient.Connect(address, port);
                byte[] sendBytes = Packet.MakeLoginPacket();
                udpClient.Send(sendBytes, sendBytes.Length);
                var receiveTask = udpClient.ReceiveAsync();
                var tsk = await Task.WhenAny(receiveTask, Task.Delay(TimeSpan.FromSeconds(TIMEOUTSEC)));
                if (tsk == receiveTask)
                {
                    var result = await receiveTask;
                    var header = ByteArrayToNewStuff(result.Buffer);
                    if (((uint)header.Flags & 0x800000u) != 0 && result.Buffer.Length >= 24)
                    {
                        byte[] newBytes = new byte[4];
                        Buffer.BlockCopy(result.Buffer, 20, newBytes, 0, 4);
                        var n = BitConverter.ToUInt32(newBytes, 0);
                        var debug = string.Format("Got {0}: ", n);
                        for (int i = 0; i < result.Buffer.Length; ++i)
                        {
                            var bytn = result.Buffer[i];
                            debug += bytn.ToString("X2");
                            if (i == 4 || i == 8 || i == 12 || i == 14 || i == 16 || i == 18 || i == 20)
                            {
                                debug += " ";
                            }
                        }
                        System.Diagnostics.Debug.WriteLine(debug);

                    }
                    // TODO - extract number of players from buffer
                    return true;
                }
                else
                {
                    // TODO: clean up udpClient?
                    return false;
                }
            }
            catch (SocketException e)
            {
                if (e.ErrorCode == 10054)
                {
                    return false;
                }
                else
                {
                    return false;
                }
            }
            finally
            {
                if (udpClient != null)
                {
                    udpClient.Close();
                    udpClient = null;
                }
            }
        }
        public static Packet.PacketHeader ByteArrayToNewStuff(byte[] bytes)
        {
            System.Runtime.InteropServices.GCHandle handle = System.Runtime.InteropServices.GCHandle.Alloc(bytes, System.Runtime.InteropServices.GCHandleType.Pinned);
            Packet.PacketHeader stuff = (Packet.PacketHeader)System.Runtime.InteropServices.Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(Packet.PacketHeader));
            handle.Free();
            return stuff;
        }

    }

    public static class Hash32
    {
        public static uint Calculate(byte[] data, int length)
        {
            uint checksum = (uint)length << 16;
            for (int i = 0; i < length && i + 4 <= length; i += 4)
                checksum += BitConverter.ToUInt32(data, i);

            int shift = 24;
            for (int i = (length / 4) * 4; i < length; i++)
            {
                checksum += (byte)(data[i] << shift);
                shift -= 8;
            }

            return checksum;
        }
    }

    internal class Packet
    {
        [Flags]
        public enum PacketHeaderFlags : uint
        {
            None = 0x00000000,
            Retransmission = 0x00000001,
            EncryptedChecksum = 0x00000002, // can't be paired with 0x00000001, see FlowQueue::DequeueAck
            BlobFragments = 0x00000004,
            ServerSwitch = 0x00000100,
            Referral = 0x00000800,
            RequestRetransmit = 0x00001000,
            RejectRetransmit = 0x00002000,
            AckSequence = 0x00004000,
            Disconnect = 0x00008000,
            LoginRequest = 0x00010000,
            WorldLoginRequest = 0x00020000,
            ConnectRequest = 0x00040000,
            ConnectResponse = 0x00080000,
            CICMDCommand = 0x00400000,
            TimeSynch = 0x01000000,
            EchoRequest = 0x02000000,
            EchoResponse = 0x04000000,
            Flow = 0x08000000
        }
        public static byte[] MakeLoginPacket()
        {
            byte[] loginPacket = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x93, 0x00, 0xd0, 0x05, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x04, 0x00, 0x31, 0x38, 0x30, 0x32, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3e, 0xb8, 0xa8, 0x58, 0x1c, 0x00, 0x61, 0x63, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x74, 0x72, 0x61, 0x63, 0x6b, 0x65, 0x72, 0x3a, 0x6a, 0x6a, 0x39, 0x68, 0x32, 0x36, 0x68, 0x63, 0x73, 0x67, 0x67, 0x63, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
            return loginPacket;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public class PacketHeader
        {
            public static uint HeaderSize { get { return 0x20u; } }

            public uint Sequence { get; set; }
            public PacketHeaderFlags Flags { get; set; }
            public uint Checksum { get; set; }
            public ushort Id { get; set; }
            public ushort Time { get; set; }
            public ushort Size { get; set; }
            public ushort Table { get; set; }

            public PacketHeader(PacketHeaderFlags flags)
            {
                this.Size = (ushort)HeaderSize;
                this.Flags = flags;
            }
            public PacketHeader() { }
            public byte[] GetRaw()
            {
                var headerHandle = GCHandle.Alloc(this, GCHandleType.Pinned);
                try
                {
                    byte[] bytes = new byte[Marshal.SizeOf(typeof(PacketHeader))];
                    Marshal.Copy(headerHandle.AddrOfPinnedObject(), bytes, 0, bytes.Length);
                    return bytes;
                }
                finally
                {
                    headerHandle.Free();
                }
            }

            public void CalculateHash32(out uint checksum)
            {
                uint original = Checksum;

                Checksum = 0x0BADD70DD;
                byte[] rawHeader = GetRaw();
                checksum = Hash32.Calculate(rawHeader, rawHeader.Length);
                Checksum = original;
            }
        }
    }
    #endregion
}
