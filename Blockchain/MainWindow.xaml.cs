using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.Security.Cryptography;
using System.Timers;
using System.Reflection;
using System.Security.Policy;
using System.Windows.Markup;

namespace Blockchain
{
    public partial class MainWindow : Window
    {
        private TcpListener listener;
        class Block
        {
            public int Index { get; set; }
            public DateTime Timestamp { get; set; }
            public string Data { get; set; }
            public string Hash { get; set; }
            public string Previous_hash { get; set; }
            public int Difficulty { get; set; }
            public int Nonce { get; set; }
            public string Miner { get; set; }

            public Block() { }

            public Block(int index_, DateTime timestamp_, string data_, string hash_, string previous_hash_, int difficulty_, int nonce_, string miner_)
            {
                Index = index_;
                Timestamp = timestamp_;
                Data = data_;
                Hash = hash_;
                Previous_hash = previous_hash_;
                Difficulty = difficulty_;
                Nonce = nonce_;
                Miner = miner_;
            }
        }

        class User
        {
            public TcpClient user_client;
            public string username;
            public User(TcpClient client_, string username_)
            {
                user_client = client_;
                username = username_;
            }
        }

        #region Konstante

        const string STD_IP = "127.0.0.1";
        int SERVER_PORT;
        int STD_PORT;
        int DIFFICULTY = 2;
        string username;
        bool run = false;

        const int packet_size_KB = 111;
        List<User> client_users = new List<User>();
        List<Block> chain = new List<Block>();
        List<User> users = new List<User>();



        #endregion

        //-------------------------------------------------------------------------------------------------------------------------------------------------
        // UI LOGIC

        async Task UpdateRichTextBoxAsync(string message)
        {
            await Application.Current.Dispatcher.InvokeAsync(() =>
            {
                if (message.StartsWith("correct"))
                {
                    miningLogBuffer.Enqueue(message);
                }
            });
        }


        //-------------------------------------------------------------------------------------------------------------------------------------------------
        // CONNECTION LOGIC


        void ServerThread()
        {
            TcpListener listener = new TcpListener(IPAddress.Parse(STD_IP), STD_PORT);
            listener.Start();

            bool run = true;
            for (int i = 0; run; i++)
            {
                info_box_block.Dispatcher.Invoke(new Action(() => info_box_block.AppendText("Poslušam!" + "\n")));
                TcpClient server_client = new TcpClient();
                server_client = listener.AcceptTcpClient();

                Thread thread = new Thread(new ParameterizedThreadStart(Connection));
                thread.Start(server_client);
            }
        }

        void Connection(object client_)
        {
            TcpClient server_client = (TcpClient)client_;

            string connection_message = Recieve(server_client);

            List<string> args = (List<string>)JsonSerializer.Deserialize(connection_message, typeof(List<string>));
            string server_username = args[1];


            if (args[0] == "C")
            {
                users.Add(new User(server_client, server_username));
                List<string> usernames = new List<string>();

                foreach (User u in users) usernames.Add(u.username);
                info_box_block.Dispatcher.Invoke(new Action(() => info_box_block.AppendText("Povezal se je uporabnik: " + server_username + "\n")));
                info_box_block.Dispatcher.Invoke(new Action(() => info_box_block.AppendText("Trenutni klienti: " + JsonSerializer.Serialize(usernames) + "\n")));
                Send(username, server_client);
            }
            else
            {
                info_box_block.Dispatcher.Invoke(new Action(() => info_box_block.AppendText("Napaka\n")));
                return;
            }

            bool run = true;
            while (run)
            {
                string message = Recieve(server_client);

                try
                {
                    args = (List<string>)JsonSerializer.Deserialize(message, typeof(List<string>));
                }
                catch (Exception ex)
                {
                    continue;
                }

                if (args[0] == "B")
                {
                    List<Block> recieved_chain = (List<Block>)JsonSerializer.Deserialize(args[1], typeof(List<Block>));
                    CompareChain(recieved_chain, server_client, server_username);
                }
                else
                {
                    info_box_block.Dispatcher.Invoke(new Action(() => info_box_block.AppendText("Napaka\n")));
                    return;
                }
            }
        }

        string Recieve(string message, TcpClient client_)
        {
            NetworkStream stream = client_.GetStream();
            try
            {
                byte[] byte_message = new byte[1024 * packet_size_KB];
                int len = stream.Read(byte_message, 0, byte_message.Length);

                string encrypted_message = Encoding.UTF8.GetString(byte_message, 0, len);
                return encrypted_message;
            }
            catch (Exception e)
            {
                MessageBox.Show("Prišlo je do napake pri pošiljanju sporočila: \n" + e.Message + "\n" + e.StackTrace);
                return null;
            }
        }

        void Send(string message, TcpClient client_)
        {
            NetworkStream stream = client_.GetStream();
            try
            {
                byte[] byte_message = Encoding.UTF8.GetBytes(message);
                stream.Write(byte_message, 0, byte_message.Length);
            }
            catch (Exception e)
            {
                Console.WriteLine("Prišlo je do napake pri pošiljanju sporočila: \n" + e.Message + "\n" + e.StackTrace);
            }
        }

        


        string Recieve(TcpClient client)
        {
            try
            {
                NetworkStream stream = client.GetStream();
                byte[] byteMessage = new byte[1024 * packet_size_KB];
                int len = stream.Read(byteMessage, 0, byteMessage.Length);
                return Encoding.UTF8.GetString(byteMessage, 0, len);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error receiving message: {ex.Message}");
                return null;
            }
        }

        



        //-------------------------------------------------------------------------------------------------------------------------------------------------
        // MINE LOGIC

        async Task Mine()
        {
            while (run)
            {
                string data = string.Empty;
                Dispatcher.Invoke(() => data = textBox1.Text);

                int index = chain.Count;
                string previousHash = chain.Count > 0 ? chain.Last().Hash : "0";

                DateTime timeStamp = DateTime.Now;
                int nonce = 0;
                bool validBlock = false;

                // Declare diffCompare based on the current DIFFICULTY
                string diffCompare = new string('0', DIFFICULTY);

                while (!validBlock && run)
                {
                    timeStamp = DateTime.Now;

                    string toHash = $"{index},{timeStamp},{data},{previousHash},{DIFFICULTY},{nonce}";
                    string currentHash = Sha256Hash(toHash);

                    float timeDiffFromNow = (float)(DateTime.Now - timeStamp).TotalMinutes;
                    float timeDiffFromPrev = chain.Count > 0 ? (float)(timeStamp - chain.Last().Timestamp).TotalMinutes : 0;

                    validBlock = currentHash.Substring(0, DIFFICULTY) == diffCompare && timeDiffFromNow < 1 && timeDiffFromPrev < 1;

                    if (!validBlock)
                    {
                        await UpdateRichTextBoxAsync($"wrong: {currentHash} diff: {DIFFICULTY}\n");
                    }

                    nonce++;
                }

                if (!run) break;

                string hashFill = Sha256Hash($"{index},{timeStamp},{data},{previousHash},{DIFFICULTY},{nonce}");

                Block newBlock = new Block(index, timeStamp, data, hashFill, previousHash, DIFFICULTY, nonce, username);
                chain.Add(newBlock);

                await UpdateRichTextBoxAsync($"correct: {newBlock.Hash} diff: {DIFFICULTY}\n");
                await UpdateRichTextBoxAsync("Broadcasting our Blockchain:\n");

                CheckTimeDiff();

                List<string> param = new List<string> { "B", JsonSerializer.Serialize(chain) };
                BroadCast(JsonSerializer.Serialize(param));
                PrintChain();
            }
        }



        string Sha256Hash(string rawData)
        {
            // Create a SHA256   
            using (SHA256 sha256Hash = SHA256.Create())
            {
                // ComputeHash - returns byte array  
                byte[] bytes = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(rawData));

                // Convert byte array to a string   
                StringBuilder builder = new StringBuilder();
                for (int i = 0; i < bytes.Length; i++)
                {
                    builder.Append(bytes[i].ToString("x2"));
                }
                return builder.ToString();
            }
        }


        //-------------------------------------------------------------------------------------------------------------------------------------------------
        // CHAIN LOGIC

        void PrintChain()
        {
            info_box_block.Dispatcher.Invoke(new Action(() =>
            {
                info_box_block.Document.Blocks.Clear();

                foreach (Block block in chain)
                {
                    info_box_block.AppendText(
                        "Block " + (block.Index + 1).ToString() + "\n" +
                        "   Miner: " + block.Miner + "\n" +
                        "   Time stamp: " + block.Timestamp + "\n" +
                        "   Previous hash: " + "\n" +
                        "       " + block.Previous_hash + "\n" +
                        "   Difficulty: " + block.Difficulty.ToString() + "\n" +
                        "   Nonce: " + block.Nonce.ToString() + "\n" +
                        "   Hash: " + "\n" +
                        "       " + block.Hash + "\n"
                    );
                }

                // Set caret position to the end for automatic scrolling
                info_box_block.ScrollToEnd();
            }));
        }


        void CompareChain(List<Block> chain_, TcpClient client_, string username_)
        {
            double comulative_diff_ours = 0;
            double comulative_diff_recv = 0;
            foreach (Block block in chain)
            {
                comulative_diff_ours += Math.Pow(2, block.Difficulty);
            }
            foreach (Block block in chain_)
            {
                comulative_diff_recv += Math.Pow(2, block.Difficulty);
            }
            if (comulative_diff_recv > comulative_diff_ours)
            {
                chain = chain_;
                info_box_mine.Dispatcher.Invoke(new Action(() => info_box_mine.AppendText("Posodobil verigo" + "\n")));
                List<string> param = new List<string>();
                param.Add("B");
                param.Add(JsonSerializer.Serialize(chain));
                BroadCast(JsonSerializer.Serialize(param));
                PrintChain();
            }
            else if (comulative_diff_recv < comulative_diff_ours)
            {
                info_box_mine.Dispatcher.Invoke(new Action(() => info_box_mine.AppendText("Nadomestil verigo" + "\n")));
                bool found = false;
                foreach (User u in client_users)
                {
                    if (u.username == username_)
                    {
                        found = true;
                        info_box_block.Dispatcher.Invoke(new Action(() => info_box_block.AppendText("Pošiljam vojo verigo pošiljatelju" + "\n")));

                        List<string> param = new List<string>();
                        param.Add("B");
                        param.Add(JsonSerializer.Serialize(chain));

                        Send(JsonSerializer.Serialize(param), u.user_client);
                    }
                }
                if (!found)
                {

                    info_box_block.Dispatcher.Invoke(new Action(() => info_box_block.AppendText("Pošiljatelj ni povezan in ne pošiljam verige" + "\n")));

                }
            }
        }

        const int diff_n_interval = 3;
        const float block_gen_time = 10;
        const float diff_sensetivity_multiplier = 2;

        void CheckTimeDiff()
        {
            if (chain.Count() < diff_n_interval || (chain.Count() % diff_n_interval) != 0) return;
            Block prevAdjBlock = chain[chain.Count() - diff_n_interval];
            float expected_time = diff_n_interval * block_gen_time;
            Block last_block = chain[chain.Count() - 1];
            float taken_time = (last_block.Timestamp - prevAdjBlock.Timestamp).Seconds;
            int t = chain.Count();
            if (taken_time < expected_time / diff_sensetivity_multiplier)
            {
                DIFFICULTY++;

                info_box_block.Dispatcher.Invoke(new Action(() => info_box_block.AppendText("!!!!" + "\n" +
                                "raised the difficulty to: " + DIFFICULTY.ToString() + "\n" +
                                "!!!!" + "\n"
                                )));
            }
            else if (taken_time > expected_time * diff_sensetivity_multiplier)
            {
                DIFFICULTY--;

                info_box_block.Dispatcher.Invoke(new Action(() => info_box_block.AppendText("!!!!" + "\n" +
                                "lowered the difficulty to: " + DIFFICULTY.ToString() + "\n" +
                                "!!!!" + "\n"
                                )));
            }
        }
        void BroadCast(string message)
        {
            foreach (User user_ in client_users)
            {
                Send(message, user_.user_client);
            }
        }


        //-------------------------------------------------------------------------------------------------------------------------------------------------
        // CLICK LOGIC
        private void Connect_Click(object sender, EventArgs e)  // connect
        {
            try
            {
                TcpClient client_client = new TcpClient();
                SERVER_PORT = Int32.Parse(text_box_connect.Text);
                client_client.Connect(STD_IP, SERVER_PORT);
                List<string> param = new List<string>();
                param.Add("C");
                param.Add(username);

                Send(JsonSerializer.Serialize(param), client_client);
                string partner_username = Recieve(client_client);
                User new_outgoing_user = new User(client_client, partner_username);
                client_users.Add(new_outgoing_user);

                info_box_block.Dispatcher.Invoke(new Action(() => info_box_block.AppendText("Povezava vspostavljena na novega uporabnika\n")));
            }
            catch (Exception eg)
            {
                MessageBox.Show("Napaka pri povezovanju \n" + eg.Message + "\n" + eg.StackTrace);
            }
        }

        private void Mine_Click(object sender, EventArgs e) // mine
        {
            if (!run)
            {
                run = true;
                Task miningTask = Task.Run(() => Mine());
            }
            else
            {
                run = false;
            }
        }

        private void Start_Click(object sender, EventArgs e) // start
        {
            STD_PORT = Int32.Parse(text_box_start.Text);
            username = text_box_start.Text;

            listener = new TcpListener(IPAddress.Parse(STD_IP), STD_PORT);

            Thread thread = new Thread(new ThreadStart(ServerThread));
            thread.Start();
        }

        //-------------------------------------------------------------------------------------------------------------------------------------------------
        // UI TIMER

        private void UiUpdateTimer_Elapsed(object state)
        {
            lock (updateLock)
            {
                if (!isUpdating && miningLogBuffer.Count > 0)
                {
                    isUpdating = true;

                    Application.Current.Dispatcher.InvokeAsync(() =>
                    {
                        string logEntry = miningLogBuffer.Dequeue();
                        info_box_mine.AppendText(logEntry);
                        info_box_mine.ScrollToEnd();

                        isUpdating = false;
                    });
                }
            }
        }

        private readonly System.Threading.Timer uiUpdateTimer;
        private readonly object updateLock = new object();
        private readonly Queue<string> miningLogBuffer = new Queue<string>();
        private bool isUpdating = false;

        //-------------------------------------------------------------------------------------------------------------------------------------------------
        // MAIN

        public MainWindow()
        {
            InitializeComponent();
            uiUpdateTimer = new System.Threading.Timer(UiUpdateTimer_Elapsed, null, 0, 1000);
        }
    }
}

