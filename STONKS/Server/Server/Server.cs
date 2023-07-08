using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using System.Windows.Forms;

namespace Server
{
    public partial class Server : Form
    {

        //DiffieHellman objekat za razmjenu kljuca
        private DiffieHellmanED.DiffieHellman serverDK = new DiffieHellmanED.DiffieHellman();
        private string dekriptovana;
        private byte[] KLJUC;
        private byte[] IV;
        private bool active = false; // Označava da li je server aktivan ili ne
        private Thread listener = null; // Nit odgovorna za slušanje klijentskih veza
        private long id = 0; // Jedinstveni identifikator za svakog povezanog klijenta
        private struct MyClient // struktura podataka za klijenta
        {
            public long id; // Jedinstveni identifikator klijenta
            public StringBuilder username; // username klijenta
            public byte[] pubKey; // public key za dekripciju
            public StringBuilder keyString; // public key za dekripciju kao string
            public byte[] IV; // initialization vector za dekripciju
            public StringBuilder IVString; // initialization vector za dekripciju kao string
            public TcpClient client; // TCP objekat za komunikaciju
            public NetworkStream stream; // Stream za slanje podataka preko mreze
            public byte[] buffer; // buffer za podatke
            public StringBuilder data; // akumulirani podaci primljeni od servera
            public EventWaitHandle handle; // event za sinhronizaciju
        };

        // ConcurrentDictionary za skladištenje povezanih klijenata, koristeći ID klijenta kao ključ
        // ConcurrentDictionary je klasa kolekcije bezbedna za nit za čuvanje parova ključ/vrednost
        // Interno koristi zaključavanje da bi nam obezbijedio klasu bezbjednu za višenitnost.
        private ConcurrentDictionary<long, MyClient> clients = new ConcurrentDictionary<long, MyClient>();

        private Task send = null; // task za slanje podataka
        private Thread disconnect = null; // Thread objekat za rukovanje klijentskim isključenjima
        private bool exit = false; // pracenje statusa aplikacije


        public Server()
        {
            
            InitializeComponent();
        }

        //metoda za upisivanje u textBox
        private void Log(string msg = "") // cisti log ako je poruka prazna
        {
            if (!exit)
            {
                logTextBox.Invoke((MethodInvoker)delegate
                {
                    if (msg.Length > 0)
                    {
                        logTextBox.AppendText(string.Format("[ {0} ] {1}{2}", DateTime.Now.ToString("HH:mm"), msg, Environment.NewLine));
                    }
                    else
                    {
                        logTextBox.Clear();
                    }
                });
            }
        }

        //metoda za generaciju poruke greske
        private string ErrorMsg(string msg)
        {
            return string.Format("ERROR: {0}", msg);
        }

        //metoda za generaciju poruke sistema
        private string SystemMsg(string msg)
        {
            return string.Format("SYSTEM: {0}", msg);
        }

        //metoda za rukovanje statusom servera
        private void Active(bool status)
        {
            if (!exit) // Provjera da li je program u procesu izlaska
            {
                startButton.Invoke((MethodInvoker)delegate
                {
                    active = status;
                    if (status)
                    {
                        //kad se server pokrene iskljucuju se kontrole za podesavanje prametara konekcije
                        //mijenja se tekst dugmeta za pokretanje i prikazuje se poruka da je server pokrenut
                        addrTextBox.Enabled = false;
                        portTextBox.Enabled = false;
                        usernameTextBox.Enabled = false;
                        keyTextBox.Enabled = false;
                        startButton.Text = "Stop";
                        Log(SystemMsg("Server has started"));
                    }
                    else
                    {
                        //ako server nije aktivan ukljucuju se kontrole za podesavanje prametara konekcije
                        //mijenja se tekst dugmeta za pokretanje i prikazuje se poruka da je server zaustavljen
                        addrTextBox.Enabled = true;
                        portTextBox.Enabled = true;
                        usernameTextBox.Enabled = true;
                        keyTextBox.Enabled = true;
                        startButton.Text = "Start";
                        Log(SystemMsg("Server has stopped"));
                    }
                });
            }
        }


        //metoda za dodavanje klijenata u listu
        private void AddToGrid(long id, string name)
        {
            if (!exit) // Provjera da li je program u procesu izlaska
            {

                // Pozivamo operaciju korisničkog interfejsa kontrole clientsDataGridView
                clientsDataGridView.Invoke((MethodInvoker)delegate
                {
                    // Kreiranje novog reda sa ID-om i imenom klijenta
                    string[] row = new string[] { id.ToString(), name };
                    // Dodavanje reda u clientsDataGridView
                    clientsDataGridView.Rows.Add(row);
                    // Ažuriranje totalLabel da bi se prikazao trenutni broj klijenata povezanih na server
                    totalLabel.Text = string.Format("Total clients: {0}", clientsDataGridView.Rows.Count);
                });
            }
        }

        //metoda za uklanjanje klijenata iz liste
        private void RemoveFromGrid(long id)
        {
            if (!exit) // Provjera da li je program u procesu izlaska
            {
                // Pozivamo operaciju korisničkog interfejsa kontrole clientsDataGridView
                clientsDataGridView.Invoke((MethodInvoker)delegate
                {
                    // Iterativno prolazimo kroz svaki red u clientsDataGridView
                    foreach (DataGridViewRow row in clientsDataGridView.Rows)
                    {
                        // Provjera da li se vrijednost u ćeliji „identifier“ poklapa sa navedenim ID-om
                        if (row.Cells["identifier"].Value.ToString() == id.ToString())
                        {
                            // Uklanjanje odgovarajućeg reda iz clientsDataGridView
                            clientsDataGridView.Rows.RemoveAt(row.Index);
                            break;
                        }
                    }

                    // Ažurirajte totalLabel da bi prikazali trenutni broj redova u mreži
                    totalLabel.Text = string.Format("Total clients: {0}", clientsDataGridView.Rows.Count);
                });
            }
        }


        // metoda za asinhrono citanje
        private void Read(IAsyncResult result)
        {

            // objekat tipa MyClient se popunjava asinhrono
            MyClient obj = (MyClient)result.AsyncState;
            int bytes = 0;

            // ako je klijent povezan
            if (obj.client.Connected)
            {
                try
                {
                    // Završi operaciju asinhronog čitanja i dobije broj pročitanih bajtova
                    bytes = obj.stream.EndRead(result);
                }
                catch (Exception ex)
                {
                    // Evidentiraj sve izuzetke koji su se desili tokom operacije čitanja
                    Log(ErrorMsg(ex.Message));
                }
            }

            // ako su pročitani bajtovi
            if (bytes > 0)
            {
                // Dodati primljene podatke podacima StringBuilder u objektu MyClient
                obj.data.AppendFormat("{0}", Encoding.UTF8.GetString(obj.buffer, 0, bytes));
                try
                {
                    // Provjeri da li ima još podataka za čitanje
                    if (obj.stream.DataAvailable)
                    {
                        // Započinjanje druge asinhrone operacije čitanja
                        obj.stream.BeginRead(obj.buffer, 0, obj.buffer.Length, new AsyncCallback(Read), obj);
                    }
                    else
                    {
                        // Svi podaci su primljeni, obradite poruku
                        string msg = string.Format("{0}: {1}", obj.username, obj.data);
                        string enkriptovanap = string.Format("{0}",obj.data);
                        //System.Diagnostics.Debug.WriteLine(obj.data.ToString());
                        // Dekripcija primljene poruke

                        JavaScriptSerializer json = new JavaScriptSerializer(); // feel free to use JSON serializer
                        //rjecnik za primljenje podatke koji se sastoji od kljuca i podataka
                        Dictionary<string, string> data = json.Deserialize<Dictionary<string, string>>(obj.data.ToString());

                        //Dictionary<string, byte[]> publicKeyData = json.Deserialize<Dictionary<string, byte[]>>(obj.data.ToString());

                        //primanje public key servera
                        if (data.ContainsKey("publicKey"))
                        {

                            dekriptovana = serverDK.Decrypt(Convert.FromBase64String(data["publicKey"]), Convert.FromBase64String(data["message"]), Convert.FromBase64String(data["IV"]));
                        }

                        /*
                        foreach (KeyValuePair<long, MyClient> klijent in clients)
                        {
                            if (klijent.Value.id == obj.id)
                            {
                                 dekriptovana = serverDK.Decrypt(Convert.FromBase64String(klijent.Value.keyString.ToString()), Convert.FromBase64String(enkriptovanap), Convert.FromBase64String(klijent.Value.IVString.ToString()));
                            }
                        }*/

                        //string dekriptovana = serverDK.Decrypt(KLJUC, Convert.FromBase64String(enkriptovanap),IV);
                        string dekriptovanaSaUserInfo = string.Format("{0}: {1}", obj.username, dekriptovana);
                        // Prikaz dekriptovane poruke
                        //Log(dekriptovana+"OVO JE TO STO JEBE KOKE");

                        Log(RemoveNonAlphaNumeric(dekriptovana));

                       /* System.Diagnostics.Debug.WriteLine(enkriptovanap);
                        System.Diagnostics.Debug.WriteLine("kljuc"+Convert.ToBase64String(KLJUC));
                        System.Diagnostics.Debug.WriteLine("IV"+Convert.ToBase64String(IV));*/

                        

                        // Slanje dekriptovane poruke drugim klijentima
                        //Send(dekriptovanaSaUserInfo, obj.id);

                        var foreachWatch = System.Diagnostics.Stopwatch.StartNew();
                        //enkripcija kroz foreach
                        foreach (KeyValuePair<long, MyClient> klijent in clients)
                        {
                            if (klijent.Value.id != obj.id)
                            {
                                MyClient tmp = new MyClient();
                                
                                long id = klijent.Value.id;
                                byte[] pubKey = Convert.FromBase64String(klijent.Value.keyString.ToString());
                                byte[] IV = Convert.FromBase64String(klijent.Value.IVString.ToString());
                                byte[] secretMessage = serverDK.Encrypt(pubKey, dekriptovanaSaUserInfo);
                                tmp.id = id;
                                tmp.pubKey = pubKey;
                                tmp.buffer = klijent.Value.buffer;
                                tmp.IV = IV;
                                tmp.handle = klijent.Value.handle;
                                tmp.client = klijent.Value.client;
                                tmp.data = klijent.Value.data;
                                tmp.IVString = klijent.Value.IVString;
                                tmp.keyString = klijent.Value.keyString;
                                tmp.stream = klijent.Value.stream;
                                Send(Poruka(secretMessage), tmp);
                                //Send(dekriptovana+"foreach", obj.id);
                                // Briše podatke StringBuilder-a za sledeću poruku
                               // obj.data.Clear();
                                tmp.data.Clear();
                                // Signalizira niti na čekanju da je operacija završena
                               // obj.handle.Set();
                                tmp.handle.Set();
                            }
                        }

                        foreachWatch.Stop();
                        
                        
                        System.Diagnostics.Debug.WriteLine("PARALELNI foreach");
                        
                        var parallelWatch = System.Diagnostics.Stopwatch.StartNew();
                        //enkripcija kroz PARALELNI foreach
                        Parallel.ForEach(clients, klijent =>
                        {
                            if (klijent.Value.id != obj.id)
                            {
                                MyClient tmp = new MyClient();
                                long id = klijent.Value.id;
                                byte[] pubKey = Convert.FromBase64String(klijent.Value.keyString.ToString());
                                byte[] IV = Convert.FromBase64String(klijent.Value.IVString.ToString());
                                byte[] secretMessage = serverDK.Encrypt(pubKey, dekriptovanaSaUserInfo);
                                tmp.id = id;
                                tmp.pubKey = pubKey;
                                tmp.buffer = klijent.Value.buffer;
                                tmp.IV = IV;
                                tmp.handle = klijent.Value.handle;
                                tmp.client = klijent.Value.client;
                                tmp.data = klijent.Value.data;
                                tmp.IVString = klijent.Value.IVString;
                                tmp.keyString = klijent.Value.keyString;
                                tmp.stream = klijent.Value.stream;
                                Send(Poruka(secretMessage), tmp);
                                //Send(dekriptovana+"foreach", obj.id);
                                // Briše podatke StringBuilder-a za sledeću poruku
                               // obj.data.Clear();
                                tmp.data.Clear();
                                // Signalizira niti na čekanju da je operacija završena
                               // obj.handle.Set();
                                tmp.handle.Set();
                            }
                        });

                        parallelWatch.Stop();
                        System.Diagnostics.Debug.WriteLine("foreach exec time: " + Convert.ToString(foreachWatch.Elapsed));
                        System.Diagnostics.Debug.WriteLine("parallel foreach exec time: " + Convert.ToString(parallelWatch.Elapsed));
                        
                        // Briše podatke StringBuilder-a za sledeću poruku
                        obj.data.Clear();
                        // Signalizira niti na čekanju da je operacija završena
                        obj.handle.Set();
                    }
                }
                catch (Exception ex)
                {
                    // Briše podatke StringBuilder-a
                    obj.data.Clear();
                    // Evidentiraj sve izuzetke koji su se desili tokom obrade
                    Log(ErrorMsg(ex.Message));
                    // Signalizira niti na čekanju da je operacija završena
                    obj.handle.Set();
                }
            }
            else
            {
                // Ako nijedan bajt nije pročitan, zatvori klijentsku vezu
                obj.client.Close();
                // Signalizira niti na čekanju da je operacija završena
                obj.handle.Set();
            }
        }

        //metoda za autentifikaciju
        private void ReadAuth(IAsyncResult result)
        {
            // Preuzimanje objekta MyClient iz AsyncState-a
            MyClient obj = (MyClient)result.AsyncState;
            int bytes = 0;
            // Provjera da li je klijent i dalje povezan
            if (obj.client.Connected)
            {
                try
                {
                    // Završavanje asinhronog čitanja i dobijanje broja pročitanih bajtova
                    bytes = obj.stream.EndRead(result);
                }
                catch (Exception ex)
                {
                    // Logovanje svih izuzetaka koji su se dogodili tokom čitanja
                    Log(ErrorMsg(ex.Message));
                }
            }

            // Provjera da li su pročitani neki bajtovi
            if (bytes > 0)
            {
                // Dodavanje primljenih podataka u StringBuilder objekta "data" u MyClient strukturi
                obj.data.AppendFormat("{0}", Encoding.UTF8.GetString(obj.buffer, 0, bytes));
                try
                {
                    // Provjera da li ima dostupnih još podataka za čitanje
                    if (obj.stream.DataAvailable)
                    {
                        // Pokretanje nove asinhrone operacije čitanja
                        obj.stream.BeginRead(obj.buffer, 0, obj.buffer.Length, new AsyncCallback(ReadAuth), obj);
                    }
                    else
                    {
                        // Deserijalizacija primljenih podataka u rječnik (dictionary)
                        JavaScriptSerializer json = new JavaScriptSerializer(); // feel free to use JSON serializer
                        Dictionary<string, string> data = json.Deserialize<Dictionary<string, string>>(obj.data.ToString());
                        // Provera da li obavezna polja postoje u podacima i da li se podudaraju sa očekivanim vrijednostima
                        if (!data.ContainsKey("username") || data["username"].Length < 1 || !data.ContainsKey("key") || !data["key"].Equals(keyTextBox.Text))
                        {
                            // Zatvaranje klijentske konekcije ako su podaci nevažeći
                            obj.client.Close();
                        }
                        else
                        {
                            // Čuvanje korisničkog imena, javnog ključa i IV-a u MyClient objektu
                            obj.username.Append(data["username"].Length > 200 ? data["username"].Substring(0, 200) : data["username"]);
                            obj.pubKey = Convert.FromBase64String(data["pubKey"]);
                            obj.keyString.Append(data["pubKey"]);
                            obj.IVString.Append(data["IV"]);
                            KLJUC = obj.pubKey;
                            obj.IV = Convert.FromBase64String(data["IV"]);
                            System.Diagnostics.Debug.WriteLine("obj.IV = "+Convert.ToBase64String(obj.IV));
                            System.Diagnostics.Debug.WriteLine("obj.IVString = "+obj.IVString);
                            System.Diagnostics.Debug.WriteLine("obj.pubKey = " + Convert.ToBase64String(obj.pubKey));
                            System.Diagnostics.Debug.WriteLine("obj.keyString = " + obj.keyString);
                            IV = obj.IV;
                            //*****************//
                            // System.Diagnostics.Debug.WriteLine(Encoding.UTF8.GetString(obj.pubKey));

                            // Slanje serverovog javnog ključa klijentu
                            Dictionary<string, string> servData = new Dictionary<string, string>();                                                       
                            servData.Add("publicKey", Convert.ToBase64String(serverDK.PublicKey));
                            servData.Add("IV", Convert.ToBase64String(serverDK.IV));
                            JavaScriptSerializer jsonServ = new JavaScriptSerializer(); 
                            Send(jsonServ.Serialize(servData),obj);
                            
                            // Slanje serverovog IV klijentu                            
                            /*Dictionary<string, string> servIV = new Dictionary<string, string>();
                              servIV.Add("IV", Convert.ToBase64String(serverDK.IV));
                              Send(jsonServ.Serialize(servIV), obj);*/

                            /*var message = new
                            {
                                status = "key",
                                publicKey = BitConverter.ToString(serverDK.PublicKey)
                            };
                            JavaScriptSerializer jsonServ = new JavaScriptSerializer();
                            //string jsonMessage = new JavaScriptSerializer().Serialize(message);
                            Send(jsonServ.Serialize(message));
                            System.Diagnostics.Debug.WriteLine(jsonServ.Serialize(message));*/
                            Send("{\"status\": \"authorized\"}", obj);
                            System.Diagnostics.Debug.WriteLine("Kljuc servera "+Convert.ToBase64String(serverDK.PublicKey));
                            System.Diagnostics.Debug.WriteLine("IV servera " + Convert.ToBase64String(serverDK.IV));
                            System.Diagnostics.Debug.WriteLine("Poslati kljuc servera " + servData["publicKey"]);
                            System.Diagnostics.Debug.WriteLine("Poslati IV servera " + servData["IV"]);

                            /////
                            // Send(Encoding.UTF8.GetString(serverDK.PublicKey),obj.id);
                        }

                        // Čišćenje StringBuilder objekta "data" za sledeću poruku
                        obj.data.Clear();
                        // Signalizacija niti na čekanju da je operacija završena
                        obj.handle.Set();
                    }
                }
                catch (Exception ex)
                {
                    // Čišćenje StringBuilder objekta "data"
                    obj.data.Clear();
                    // Logovanje svih izuzetaka koji su se dogodili tokom obrade
                    Log(ErrorMsg(ex.Message));
                    // Signalizacija niti na čekanju da je operacija završena
                    obj.handle.Set();
                }
            }
            else
            {
                // Ako nisu pročitani bajtovi, zatvara se klijentska konekcija
                obj.client.Close();
                // Signalizacija niti na čekanju da je operacija završena
                obj.handle.Set();
            }
        }

        // metoda za autorizaciju
        private bool Authorize(MyClient obj)
        {
            bool success = false; // podrazumijevano neuspješna pa provjeravamo da li je uspješna
            // Petlja se izvršava sve dok je klijent povezan
            while (obj.client.Connected)
            {
                try
                {
                    // Pokretanje asinhrone operacije čitanja
                    obj.stream.BeginRead(obj.buffer, 0, obj.buffer.Length, new AsyncCallback(ReadAuth), obj);
                    // Čekanje na završetak operacije čitanja
                    obj.handle.WaitOne();
                    // Provjera da li je korisničko ime postavljeno
                    if (obj.username.Length > 0)
                    {
                        success = true;

                       
                        break;
                    }
                }
                catch (Exception ex)
                {
                    // Logovanje svih izuzetaka koji su se dogodili tokom autorizacije
                    Log(ErrorMsg(ex.Message));
                }
            }
            return success; // vraća status
        }

        // metoda za konekciju
        private void Connection(MyClient obj)
        {
            // ako je klijent autorizovan
            if (Authorize(obj))
            {
                // pokušavamo dodavanje klijenta
                clients.TryAdd(obj.id, obj);
                // dodajemo klijenta u grid
                AddToGrid(obj.id, obj.username.ToString());
                // prikazuje poruku sa imenom klijenta
                string msg = string.Format("{0} has connected", obj.username);


                
                /*Parallel.ForEach(clients.Values, client =>
                {
                    long clientId = client.id;
                    byte[] pubKey = client.pubKey;
                    byte[] IV = client.IV;

                    // Use the retrieved values as needed
                    System.Diagnostics.Debug.WriteLine("ajde sad");
                    System.Diagnostics.Debug.WriteLine($"Client ID: {clientId}, PublicKey: {BitConverter.ToString(pubKey)}, IV: {BitConverter.ToString(IV)}");
                });*/
                //*********//
                //System.Diagnostics.Debug.WriteLine(obj.username);
                // Logovanje poruke
                Log(SystemMsg(msg));
                // Slanje poruke ostalim klijentima

                foreach (KeyValuePair<long, MyClient> klijent in clients)
                {
                    if (klijent.Value.id != obj.id)
                    {
                        MyClient tmpConnected = new MyClient();

                        long id = klijent.Value.id;
                        byte[] pubKey = Convert.FromBase64String(klijent.Value.keyString.ToString());
                        byte[] IV = Convert.FromBase64String(klijent.Value.IVString.ToString());
                        byte[] secretMessage = serverDK.Encrypt(pubKey, SystemMsg(msg));
                        tmpConnected.id = id;
                        tmpConnected.pubKey = pubKey;
                        tmpConnected.buffer = klijent.Value.buffer;
                        tmpConnected.IV = IV;
                        tmpConnected.handle = klijent.Value.handle;
                        tmpConnected.client = klijent.Value.client;
                        tmpConnected.data = klijent.Value.data;
                        tmpConnected.IVString = klijent.Value.IVString;
                        tmpConnected.keyString = klijent.Value.keyString;
                        tmpConnected.stream = klijent.Value.stream;
                        Send(Poruka(secretMessage), tmpConnected);
                        //Send(dekriptovana+"foreach", obj.id);
                        // Briše podatke StringBuilder-a za sledeću poruku
                        // obj.data.Clear();
                        tmpConnected.data.Clear();
                        // Signalizira niti na čekanju da je operacija završena
                        // obj.handle.Set();
                        tmpConnected.handle.Set();
                    }
                }
               // Send(SystemMsg(msg), obj.id);



                // ovo ispod je blok za testiranje paralelizma
                // za testiranje koristen prikaz podataka iz rjecnika clients
                // sto vise klijenata paralelizam bolji
                // za jednog klijenta paralelizam je sporiji

                /*

                System.Diagnostics.Debug.WriteLine("foreach");

                var foreachWatch = System.Diagnostics.Stopwatch.StartNew();
                //prikaz podataka o klijentima kroz foreach
                foreach (KeyValuePair<long, MyClient> klijent in clients)
                {
                    long id = klijent.Value.id;
                    byte[] pubKey = Convert.FromBase64String(klijent.Value.keyString.ToString());
                    byte[] IV = Convert.FromBase64String(klijent.Value.IVString.ToString());
                    System.Diagnostics.Debug.WriteLine($"Client ID: {id}, PublicKey: {Convert.ToBase64String(pubKey)}, IV: {Convert.ToBase64String(IV)}");
                    // System.Diagnostics.Debug.WriteLine($"Client ID: {klijent.Value.id}");
                    System.Diagnostics.Debug.WriteLine("KLJUC"+Convert.ToBase64String(KLJUC));
                }

                foreachWatch.Stop();
                System.Diagnostics.Debug.WriteLine("foreach exec time: "+Convert.ToString(foreachWatch.Elapsed));

                System.Diagnostics.Debug.WriteLine("PARALELNI foreach");

                var parallelWatch = System.Diagnostics.Stopwatch.StartNew();
                //prikaz podataka o klijentima kroz PARALELNI foreach
                Parallel.ForEach(clients, klijent =>
                {
                    long id = klijent.Value.id;
                    byte[] pubKey = Convert.FromBase64String(klijent.Value.keyString.ToString());
                    byte[] IV = Convert.FromBase64String(klijent.Value.IVString.ToString());

                    // Perform the desired operations with the retrieved values
                    System.Diagnostics.Debug.WriteLine($"Client ID: {id}, PublicKey: {Convert.ToBase64String(pubKey)}, IV: {Convert.ToBase64String(IV)}");
                });

                parallelWatch.Stop();
                System.Diagnostics.Debug.WriteLine("parallel foreach exec time: " + Convert.ToString(parallelWatch.Elapsed));

                */


                /* foreach (var kvp in clients)
                 {
                     MyClient client = kvp.Value;

                     byte[] pubKey = client.pubKey; // Retrieve the pubKey value
                     byte[] IV = client.IV; // Retrieve the IV value

                     // Use the retrieved values as needed
                     System.Diagnostics.Debug.WriteLine($"Client ID: {client.id}, PublicKey: {BitConverter.ToString(pubKey)}, IV: {BitConverter.ToString(IV)}");
                 }*/

                // Petlja se izvršava sve dok je klijent povezan
                while (obj.client.Connected)
                {
                    try
                    {
                        // Pokretanje asinhrone operacije čitanja
                        obj.stream.BeginRead(obj.buffer, 0, obj.buffer.Length, new AsyncCallback(Read), obj);
                        // Čekanje na završetak operacije čitanja 
                        obj.handle.WaitOne();
                    }
                    catch (Exception ex)
                    {
                        // Logovanje svih izuzetaka koji su se dogodili tokom čitanja
                        Log(ErrorMsg(ex.Message));
                    }
                }
                // zatvaranje konekcije
                obj.client.Close();
                // uklanjanje klijenta
                clients.TryRemove(obj.id, out MyClient tmp);
                // uklanjanje iz grida
                RemoveFromGrid(tmp.id);
                // poruka da je klijent diskonektovan
                msg = string.Format("{0} has disconnected", tmp.username);
                // logovanje poruke
                Log(SystemMsg(msg));
                // slanje poruke ostalim klijentima

                foreach (KeyValuePair<long, MyClient> klijent in clients)
                {
                    if (klijent.Value.id != obj.id)
                    {
                        MyClient tmpDisconnected = new MyClient();

                        long id = klijent.Value.id;
                        byte[] pubKey = Convert.FromBase64String(klijent.Value.keyString.ToString());
                        byte[] IV = Convert.FromBase64String(klijent.Value.IVString.ToString());
                        byte[] secretMessage = serverDK.Encrypt(pubKey, msg);
                        tmpDisconnected.id = id;
                        tmpDisconnected.pubKey = pubKey;
                        tmpDisconnected.buffer = klijent.Value.buffer;
                        tmpDisconnected.IV = IV;
                        tmpDisconnected.handle = klijent.Value.handle;
                        tmpDisconnected.client = klijent.Value.client;
                        tmpDisconnected.data = klijent.Value.data;
                        tmpDisconnected.IVString = klijent.Value.IVString;
                        tmpDisconnected.keyString = klijent.Value.keyString;
                        tmpDisconnected.stream = klijent.Value.stream;
                        Send(Poruka(secretMessage), tmpDisconnected);
                        //Send(dekriptovana+"foreach", obj.id);
                        // Briše podatke StringBuilder-a za sledeću poruku
                        // obj.data.Clear();
                        tmpDisconnected.data.Clear();
                        // Signalizira niti na čekanju da je operacija završena
                        // obj.handle.Set();
                        tmpDisconnected.handle.Set();
                    }
                }
               // Send(msg, tmp.id);
            }
        }

        // metoda za osluskivanje na ip adresi i portu 
        private void Listener(IPAddress ip, int port)
        {
            
            TcpListener listener = null;
            try
            {
                // Kreiraj TcpListener objekat i pokreni slušanje na određenoj IP adresi i portu
                listener = new TcpListener(ip, port);
                listener.Start();
                Active(true);
                // Slušaj sve dok je aktivno
                while (active)
                {
                    if (listener.Pending())
                    {
                        try
                        {
                            // Kreiraj novi MyClient objekat za prihvaćenu vezu
                            MyClient obj = new MyClient();
                            obj.id = id;
                            //postavljanje pubkey i iv za cuvanje u rjecniku
                            obj.keyString = new StringBuilder();
                            obj.IVString = new StringBuilder();
                            obj.username = new StringBuilder();                            
                            obj.client = listener.AcceptTcpClient();
                            obj.stream = obj.client.GetStream();
                            obj.buffer = new byte[obj.client.ReceiveBufferSize];
                            obj.data = new StringBuilder();
                            obj.handle = new EventWaitHandle(false, EventResetMode.AutoReset);
                            // Pokreni novu nit za obradu veze
                            Thread th = new Thread(() => Connection(obj))
                            {
                                IsBackground = true
                            };
                            th.Start();
                            id++;
                        }
                        catch (Exception ex)
                        {
                            // Loguj izuzetak ako dođe do greške prilikom prihvatanja veze
                            Log(ErrorMsg(ex.Message));
                        }
                    }
                    else
                    {
                        // Čekaj 500ms ako nema novih veza
                        Thread.Sleep(500);
                    }
                }
                Active(false);
            }
            catch (Exception ex)
            {
                // Loguj izuzetak ako dođe do greške prilikom pokretanja listenera
                Log(ErrorMsg(ex.Message));
            }
            finally
            {
                if (listener != null)
                {
                    // Zatvori listenera kada završi
                    listener.Server.Close();
                }
            }
        }


        //listener za klik na StartButton
        private void StartButton_Click(object sender, EventArgs e)
        {
            if (active)
            {
                // Ako je već aktivno, zaustavi slušanje
                active = false;
            }
            // Ako listener nije pokrenut ili nije aktivan, pokreni slušanje
            else if (listener == null || !listener.IsAlive)
            {
                // Kupi unjete vrijednosti adrese, broja porta i korisničkog imena iz TextBox kontrola
                string address = addrTextBox.Text.Trim();
                string number = portTextBox.Text.Trim();
                string username = usernameTextBox.Text.Trim();
                bool error = false;
                IPAddress ip = null;

                // Provjera da li je unijeta adresa
                if (address.Length < 1)
                {
                    error = true;
                    Log(SystemMsg("Address is required")); // Adresa je obavezna
                }
                else
                {
                    try
                    {
                        ip = Dns.Resolve(address).AddressList[0];
                    }
                    catch
                    {
                        error = true;
                        Log(SystemMsg("Address is not valid")); // Adresa nije validna
                    }
                }
                int port = -1;

                // Provjera da li je unijet broj porta i da li je validan
                if (number.Length < 1)
                {
                    error = true;
                    Log(SystemMsg("Port number is required")); // Broj porta je obavezan
                }
                else if (!int.TryParse(number, out port))
                {
                    error = true;
                    Log(SystemMsg("Port number is not valid")); // Broj porta nije validan
                }
                else if (port < 0 || port > 65535)
                {
                    error = true;
                    Log(SystemMsg("Port number is out of range")); // Broj porta je van dozvoljenog opsega
                }
                // Provjera da li je uneto korisničko ime
                if (username.Length < 1)
                {
                    error = true;
                    Log(SystemMsg("Username is required")); // Korisničko ime je obavezno
                }

                // Ako nema grešaka, pokreni slušanje
                if (!error)
                {
                    listener = new Thread(() => Listener(ip, port))
                    {
                        IsBackground = true
                    };
                    listener.Start();
                }
            }
        }

        // metoda za pisanje podataka klijentima
        private void Write(IAsyncResult result)
        {
            MyClient obj = (MyClient)result.AsyncState;
            // ako je ostvarena konekcija
            if (obj.client.Connected)
            {
                try
                {
                    obj.stream.EndWrite(result); // Završi pisanje podataka
                }
                catch (Exception ex)
                {
                    Log(ErrorMsg(ex.Message)); // Logovanje eventualnih grešaka
                }
            }
        }

        // Metoda za početak pisanja poruke ka određenom klijentu
        private void BeginWrite(string msg, MyClient obj)
        {
            byte[] buffer = Encoding.UTF8.GetBytes(msg);
            // Provjera da li je ostvarena konekcija sa klijentom
            if (obj.client.Connected)
            {
                try
                {
                    // Početak asinhronog pisanja podataka ka klijentu
                    obj.stream.BeginWrite(buffer, 0, buffer.Length, new AsyncCallback(Write), obj);
                }
                catch (Exception ex)
                {
                    Log(ErrorMsg(ex.Message)); // Logovanje eventualnih grešaka
                }
            }
        }

        // Metoda za početak pisanja poruke svim klijentima, osim pošiljaocu ili za slanje svima ako je ID manji od nule
        private void BeginWrite(string msg, long id = -1)
        {
            byte[] buffer = Encoding.UTF8.GetBytes(msg);
            foreach (KeyValuePair<long, MyClient> obj in clients)
            {
                // Provjera da li je ID različit od ID-a pošiljaoca i da li je klijent povezan
                if (id != obj.Value.id && obj.Value.client.Connected)
                {
                    try
                    {
                        // Početak asinhronog pisanja podataka ka klijentu
                        obj.Value.stream.BeginWrite(buffer, 0, buffer.Length, new AsyncCallback(Write), obj.Value);
                    }
                    catch (Exception ex)
                    {
                        Log(ErrorMsg(ex.Message)); // Logovanje eventualnih grešaka
                    }
                }
            }
        }

        // metoda za slanje poruka ka određenom klijentu
        private void Send(string msg, MyClient obj)
        {
            if (send == null || send.IsCompleted)
            {
                // Ako ne postoji trenutno izvršavanje zadatka ili je prethodni zadatak završen, pokreni novi zadatak
                send = Task.Factory.StartNew(() => BeginWrite(msg, obj));
            }
            else
            {
                // Ako postoji trenutno izvršavanje zadatka, nastavi sa izvršavanjem nakon završetka prethodnog zadatka
                send.ContinueWith(antecendent => BeginWrite(msg, obj));
            }
        }

        // Ova metoda koristi se za slanje poruke svim klijentima
        // osim onome čiji je identifikator (id) jednak onome koji je prosleđen kao argument
        private void Send(string msg, long id = -1)
        {
            if (send == null || send.IsCompleted)
            {
                // Ako ne postoji trenutno izvršavanje zadatka ili je prethodni zadatak završen, pokreni novi zadatak
                send = Task.Factory.StartNew(() => BeginWrite(msg, id));
            }
            else
            {
                // Ako postoji trenutno izvršavanje zadatka, nastavi sa izvršavanjem nakon završetka prethodnog zadatka
                send.ContinueWith(antecendent => BeginWrite(msg, id));
            }
        }

        //Ova metoda se poziva kada korisnik pritisne Enter u tekstualnom polju sendTextBox
        private void SendTextBox_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.KeyCode == Keys.Enter)
            {
                e.Handled = true;
                e.SuppressKeyPress = true;
                if (sendTextBox.Text.Length > 0)
                {
                    // Provjeri da li je pritisnut Enter i tekstualno polje (sendTextBox) nije prazno
                    string msg = sendTextBox.Text;
                    sendTextBox.Clear();
                    // Loguj poruku koju korisnik šalje
                    Log(string.Format("{0} (You): {1}", usernameTextBox.Text.Trim(), msg));
                    // Pošalji poruku svim klijentima

                    foreach (KeyValuePair<long, MyClient> klijent in clients)
                    {
                        
                            MyClient tmpSend = new MyClient();

                            long id = klijent.Value.id;
                            byte[] pubKey = Convert.FromBase64String(klijent.Value.keyString.ToString());
                            byte[] IV = Convert.FromBase64String(klijent.Value.IVString.ToString());
                            byte[] secretMessage = serverDK.Encrypt(pubKey, string.Format("{0} (You): {1}", usernameTextBox.Text.Trim(), msg));
                        tmpSend.id = id;
                        tmpSend.pubKey = pubKey;
                        tmpSend.buffer = klijent.Value.buffer;
                        tmpSend.IV = IV;
                        tmpSend.handle = klijent.Value.handle;
                        tmpSend.client = klijent.Value.client;
                        tmpSend.data = klijent.Value.data;
                        tmpSend.IVString = klijent.Value.IVString;
                        tmpSend.keyString = klijent.Value.keyString;
                        tmpSend.stream = klijent.Value.stream;
                            Send(Poruka(secretMessage), tmpSend);
                        //Send(dekriptovana+"foreach", obj.id);
                        // Briše podatke StringBuilder-a za sledeću poruku
                        // obj.data.Clear();
                        tmpSend.data.Clear();
                        // Signalizira niti na čekanju da je operacija završena
                        // obj.handle.Set();
                        tmpSend.handle.Set();
                        
                    }
                   // Send(string.Format("{0}: {1}", usernameTextBox.Text.Trim(), msg));
                }
            }
        }


        // metoda se za prekid konekcije sa klijentima
        // ako ID nije dostavljen i manji je od nule, diskonektuj sve klijente
        // ako je ID dostavljen i veći ili jednak nuli, diskonektuj samo tog klijenta
        private void Disconnect(long id = -1)
        {
            if (disconnect == null || !disconnect.IsAlive)
            {
                disconnect = new Thread(() =>
                {
                    if (id >= 0)
                    {
                        // ako je ID dostavljen i veći ili jednak nuli, diskonektuj samo tog klijenta
                        clients.TryGetValue(id, out MyClient obj);
                        obj.client.Close();
                        RemoveFromGrid(obj.id);
                    }
                    else
                    {
                        // ako ID nije dostavljen ili je manji od nule, diskonektuj sve klijente
                        foreach (KeyValuePair<long, MyClient> obj in clients)
                        {
                            obj.Value.client.Close();
                            RemoveFromGrid(obj.Value.id);
                        }
                    }
                })
                {
                    IsBackground = true
                };
                disconnect.Start();
            }
        }

        //formatiranje stringa
        static string RemoveNonAlphaNumeric(string input)
        {
            // Regex pattern to match non-alphanumeric characters
            //string pattern = @"[^a-zA-Z0-9\s\p{P}]";
            //string pattern = @"[^\p{L}0-9\s\p{P}đžšćč]";
            string pattern = @"[^\p{L}0-9\s\p{P}đžšćč]+";

            // Remove non-alphanumeric characters using Regex.Replace
            string result = Regex.Replace(input, pattern, "");

            return result;
        }

        // DisconnectButton listener
        // Poziva se metoda Disconnect() bez dostavljanja ID-a, što rezultira diskonekcijom svih klijenata
        private void DisconnectButton_Click(object sender, EventArgs e)
        {
            Disconnect();
        }

        // Ova metoda se poziva kada se forma zatvara
        // Postavlja se vrednost exit na true, active na false
        // i poziva se metoda Disconnect() kako bi se obezbjedila diskonekcija svih klijenata prije zatvaranja servera
        private void Server_FormClosing(object sender, FormClosingEventArgs e)
        {
            exit = true;
            active = false;
            Disconnect();
        }
        

        // Ova metoda se poziva kada se klikne na ćeliju u DataGridView kontrolu za prikaz klijenata
        // Provjerava se da li je kliknuta ćelija u koloni "dc" (disconnect)
        // a zatim se izvodi diskonekcija klijenta čiji je identifikator izvučen iz selektovane reda
        // Metoda Disconnect() se poziva sa dobijenim identifikatorom kako bi se klijent diskonektovao.
        private void ClientsDataGridView_CellClick(object sender, DataGridViewCellEventArgs e)
        {
            if (e.RowIndex >= 0 && e.ColumnIndex == clientsDataGridView.Columns["dc"].Index)
            {
                long.TryParse(clientsDataGridView.Rows[e.RowIndex].Cells["identifier"].Value.ToString(), out long id);
                Disconnect(id);
            }
        }

        // cisti sadrzaj textBoxa
        private void ClearButton_Click(object sender, EventArgs e)
        {
            Log();
        }

        // listener za checkbox kojim se bira da li se prikazuje kljuc za povezivanje
        private void CheckBox_CheckedChanged(object sender, EventArgs e)
        {
            if (keyTextBox.PasswordChar == '*') // ako je PasswordChar == '*' to znaci da je skriveno
            {
                keyTextBox.PasswordChar = '\0'; // uklanja se maska
            }
            else
            {
                keyTextBox.PasswordChar = '*'; // postavlja masku *
            }
        }

        private string Poruka(byte[] enkriptovana)
        {
            Dictionary<string, string> servMsg = new Dictionary<string, string>();
            servMsg.Add("publicKey", Convert.ToBase64String(serverDK.PublicKey));
            servMsg.Add("IV", Convert.ToBase64String(serverDK.IV));
            servMsg.Add("message", Convert.ToBase64String(enkriptovana));
            JavaScriptSerializer jsonServ = new JavaScriptSerializer();

            return (jsonServ.Serialize(servMsg));
        }
    }
}
