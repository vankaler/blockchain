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
using System.Security.Cryptography;

namespace Blockchain
{
    public partial class MainWindow : Window
    {
        private TcpListener listener;

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
        // CLASSES

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

        

        //-------------------------------------------------------------------------------------------------------------------------------------------------
        // UI LOGIC

        async Task UpdateRichTextBoxAsync(string message) 
        {
            await Application.Current.Dispatcher.InvokeAsync(() => // lambda funkcijo sem uporabil za izvajanje na glavni niti
            {
                if (message.StartsWith("correct"))  // preverja ce se sporocila zacne s correct
                {
                    miningLogBuffer.Enqueue(message); // tukaj sem uporabil queue (vrsto) za hranjenje sporocil
                }
            });
        }


        //-------------------------------------------------------------------------------------------------------------------------------------------------
        // CONNECTION LOGIC


        void ServerThread() // predstavlja glavno nit streznika
        {
            TcpListener listener = new TcpListener(IPAddress.Parse(STD_IP), STD_PORT);
            listener.Start();

            bool run = true;
            for (int i = 0; run; i++) // zanka se izvaja neskoncno dolgo dokler je run enako true
            {
                info_box_block.Dispatcher.Invoke(new Action(() => info_box_block.AppendText("I am listening!" + "\n")));
                TcpClient server_client = new TcpClient();
                server_client = listener.AcceptTcpClient();

                Thread thread = new Thread(new ParameterizedThreadStart(Connection)); // za vsako novo povezavo se ustvari nova nit
                thread.Start(server_client);
            }
        }

        void Connection(object client_)
        {
            TcpClient server_client = (TcpClient)client_; // pretvori

            string connection_message = Recieve(server_client); // sprejme sporocilo s klicem funkcije recieve

            List<string> args = (List<string>)JsonSerializer.Deserialize(connection_message, typeof(List<string>)); // deserealizira sporocilo v seznam nizov List<string>

            string server_username = args[1]; // vzame uporabnisko ime iz seznama


            if (args[0] == "C") // preveri ce je sporocilo tipa C (ce je se je uporabnik povezal)
            {
                users.Add(new User(server_client, server_username));
                List<string> usernames = new List<string>(); // pripravi seznam uporabniskih imen za posodobitev

                foreach (User u in users) usernames.Add(u.username);
                info_box_block.Dispatcher.Invoke(new Action(() => info_box_block.AppendText("Connection with a username: " + server_username + "\n")));
                info_box_block.Dispatcher.Invoke(new Action(() => info_box_block.AppendText("Current client: " + JsonSerializer.Serialize(usernames) + "\n")));
                Send(username, server_client);
            }
            else // ce sporocilo ni tipa C javi napako
            {
                info_box_block.Dispatcher.Invoke(new Action(() => info_box_block.AppendText("Error!\n")));
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

                if (args[0] == "B") // preveri ce je sporocilo tipa B (kar pomeni prenos verige)
                {
                    List<Block> recieved_chain = (List<Block>)JsonSerializer.Deserialize(args[1], typeof(List<Block>));
                    CompareChain(recieved_chain, server_client, server_username); // klicem funkcijo za primerjanje verige s trenutno verigo na strezniku
                }
                else // ce ni tipa B javi napako
                {
                    info_box_block.Dispatcher.Invoke(new Action(() => info_box_block.AppendText("Error!\n")));
                    return;
                }
            }
        }

        

        void Send(string message, TcpClient client_) // legit copy paste iz presnjih nalog
        {
            NetworkStream stream = client_.GetStream();
            try
            {
                byte[] byte_message = Encoding.UTF8.GetBytes(message);
                stream.Write(byte_message, 0, byte_message.Length);
            }
            catch (Exception e)
            {
                Console.WriteLine("Error accured when sending a message: \n" + e.Message + "\n" + e.StackTrace);
            }
        }

        


        string Recieve(TcpClient client) // legit copy paste iz presnjih nalog
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
                Dispatcher.Invoke(() => data = textBox1.Text); // pridobi podatke za rudarjenje iz textBox1. Dispatcher.Invoke se uporablja za pravilno dostopanje do uporabniškega vmesnika, ker se ta del izvaja v drugi niti.

                int index = chain.Count;
                string previousHash = chain.Count > 0 ? chain.Last().Hash : "0"; // določa indeks novega bloka in prejšnji hash v verigi. Če je veriga prazna, se prejšnji hash postavi na "0".

                DateTime timeStamp = DateTime.Now;
                int nonce = 0;
                bool validBlock = false;

                // Declare diffCompare based on the current DIFFICULTY
                string diffCompare = new string('0', DIFFICULTY);

                while (!validBlock && run)
                {
                    timeStamp = DateTime.Now;

                    string toHash = $"{index},{timeStamp},{data},{previousHash},{DIFFICULTY},{nonce}"; // sestavi niz, ki ga je treba hashirati za preverjanje veljavnosti bloka.
                    string currentHash = Sha256Hash(toHash); // izracuna trenutni hash bloka

                    float timeDiffFromNow = (float)(DateTime.Now - timeStamp).TotalMinutes;
                    float timeDiffFromPrev = chain.Count > 0 ? (float)(timeStamp - chain.Last().Timestamp).TotalMinutes : 0;

                    validBlock = currentHash.Substring(0, DIFFICULTY) == diffCompare && timeDiffFromNow < 1 && timeDiffFromPrev < 1; // preveri, ali je trenutni hash dovolj tezak, in casovni pogoji so izpolnjeni.

                    if (!validBlock) // ce trenutni blok ni veljaven, se izvede asinhrono posodabljanje uporabniškega vmesnika s sporočilom o napaki.
                    {
                        await UpdateRichTextBoxAsync($"wrong: {currentHash} diff: {DIFFICULTY}\n");
                    }

                    nonce++;
                }

                if (!run) break;

                string hashFill = Sha256Hash($"{index},{timeStamp},{data},{previousHash},{DIFFICULTY},{nonce}"); // izracuna koncni hash bloka

                Block newBlock = new Block(index, timeStamp, data, hashFill, previousHash, DIFFICULTY, nonce, username); // ustvari nov blok s posodobljenimi podatki
                chain.Add(newBlock);

                await UpdateRichTextBoxAsync($"correct: {newBlock.Hash} diff: {DIFFICULTY}\n");
                await UpdateRichTextBoxAsync("Broadcasting our Blockchain:\n");

                CheckTimeDiff();

                List<string> param = new List<string> { "B", JsonSerializer.Serialize(chain) };
                BroadCast(JsonSerializer.Serialize(param)); // adda sporocilo na vse povezane odjemalce
                PrintChain();
            }
        }



        string Sha256Hash(string rawData)
        {
            using (SHA256 sha256Hash = SHA256.Create()) 
            { 
                byte[] bytes = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(rawData)); // izračunaj hash iz vnešenih (rawData)

                StringBuilder builder = new StringBuilder(); // StringBuilder za sestavljanje niza v heksadecimalni obliki

                for (int i = 0; i < bytes.Length; i++) // zanka, ki gre skozi vsak bajt hasha.
                {
                    builder.Append(bytes[i].ToString("x2")); // pretvori vsak bajt hasha v heksadecimalno obliko in dodaj k rezultatu
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
                info_box_block.ScrollToEnd(); // avtomatsko scrollanje na dno
            }));
        }


        void CompareChain(List<Block> chain_, TcpClient client_, string username_)
        {
            double comulative_diff_ours = 0;
            double comulative_diff_recv = 0;

            foreach (Block block in chain)
            {
                comulative_diff_ours += Math.Pow(2, block.Difficulty); // izracuna skupno težavnost blokov v lokalni verigi (chain)
            }
            foreach (Block block in chain_)
            {
                comulative_diff_recv += Math.Pow(2, block.Difficulty); // izracuna skupno težavnost blokov v prejeti verigi (chain_)
            }
            if (comulative_diff_recv > comulative_diff_ours) 
            {
                // ce je težavnost prejete verige večja od lokalne, posodobi lokalno verigo
                chain = chain_;
                info_box_mine.Dispatcher.Invoke(new Action(() => info_box_mine.AppendText("Posodobil verigo" + "\n")));
                // pripravi sporočilo za oddajanje posodobljene verige na druge povezane odjemalce
                List<string> param = new List<string>();
                param.Add("B");
                param.Add(JsonSerializer.Serialize(chain));

                BroadCast(JsonSerializer.Serialize(param)); // odda sporocilo na vse povezane odjemalce
                PrintChain();
            }
            else if (comulative_diff_recv < comulative_diff_ours)
            {
                // ce je težavnost prejete verige manjša od lokalne, nadomesti lokalno verigo z novo
                info_box_mine.Dispatcher.Invoke(new Action(() => info_box_mine.AppendText("Nadomestil verigo" + "\n")));
                bool found = false;

                foreach (User u in client_users) // preveri, ali je pošiljatelj (uporabnik z imenom username_) povezan
                {
                    if (u.username == username_)
                    {
                        found = true;
                        info_box_block.Dispatcher.Invoke(new Action(() => info_box_block.AppendText("Pošiljam vojo verigo pošiljatelju" + "\n")));
                        // pripravim sporočilo za oddajanje lokalne verige pošiljatelju
                        List<string> param = new List<string>();
                        param.Add("B");
                        param.Add(JsonSerializer.Serialize(chain));

                        
                        Send(JsonSerializer.Serialize(param), u.user_client); // poslje sporocilo psiljatelju
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

        void CheckTimeDiff() // s to metodo preverjam razliko v casu med generiranjem blokov v verigi in glede na to prilagaja tezavnost rudarjenja
        {
            if (chain.Count() < diff_n_interval || (chain.Count() % diff_n_interval) != 0) return; // preveri, ali je dovolj blokov v verigi za izvedbo preverjanja
            Block prevAdjBlock = chain[chain.Count() - diff_n_interval]; // pridobim zadnji blok v trenutni verigi
            float expected_time = diff_n_interval * block_gen_time; // pričakovani čas generiranja diff_n_interval blokov
            Block last_block = chain[chain.Count() - 1];
            float taken_time = (last_block.Timestamp - prevAdjBlock.Timestamp).Seconds;
            int t = chain.Count();
            if (taken_time < expected_time / diff_sensetivity_multiplier) // ce je cas prenizek poveca tezavnost rudarjenja
            {
                DIFFICULTY++;

                info_box_block.Dispatcher.Invoke(new Action(() => info_box_block.AppendText("!!!!" + "\n" +
                                "raised the difficulty to: " + DIFFICULTY.ToString() + "\n" +
                                "!!!!" + "\n"
                                )));
            }
            else if (taken_time > expected_time * diff_sensetivity_multiplier) // ce je cas previsok zmanjsa tezavnost rudarjenja
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

                info_box_block.Dispatcher.Invoke(new Action(() => info_box_block.AppendText("Connection established with a new user!\n")));
            }
            catch (Exception eg)
            {
                MessageBox.Show("Error accured when connecting!\n" + eg.Message + "\n" + eg.StackTrace);
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

