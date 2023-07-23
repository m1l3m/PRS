using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using System.Windows.Forms;
using System.IO;
using System.Linq;

namespace Client
{
    public partial class Client : Form
    {
        //DiffieHellman objekat za razmjenu kljuca
        private DiffieHellmanED.DiffieHellman klijentDK = new DiffieHellmanED.DiffieHellman();
        public byte[] serverKey; // cuva public key servera
        private string receivedServerKey; // cuva public key servera kao string
        public byte[] serverIV; // cuva IV servera
        private string receivedServerIV; // cuva IV servera kao string
        public string enkriptovanaPorukaServera;
        private bool connected = false; // prati status konekcije
        private Thread client = null; // thread za obradu konekcije
        private struct MyClient // klijent struktura podataka
        {
            public string username; // username klijenta
            public string key; // kljuc za povezivanje na server (ako je potreban)
            public byte[] pubKey; // public key
            public byte[] IV; // Initialization vector
            public TcpClient client; // TCP objekat za komunikaciju
            public NetworkStream stream; // Stream za slanje podataka preko mreze
            public byte[] buffer; // buffer za podatke
            public StringBuilder data; // akumulirani podaci primljeni od servera
            public EventWaitHandle handle; // event za sinhronizaciju
        };
        private MyClient obj; // klijent objekat za cuvanje podataka o konekciji
        private Task send = null; // task za slanje podataka
        private bool exit = false; // pracenje statusa aplikacije

        public Client()
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

                        logTextBox.AppendText(string.Format("[ {0} ] {1}{2}", DateTime.Now.ToString("HH:mm"), (RemoveNonAlphaNumeric(msg)), Environment.NewLine));
                        // logTextBox.AppendText(msg);
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


        //metoda za rukovanje statusom konekcije
        private void Connected(bool status)
        {
            if (!exit)
            {
                connectButton.Invoke((MethodInvoker)delegate
                {
                    connected = status;
                    if (status)
                    {
                        //kad se uspostavi konekcija iskljucuju se kontrole za podesavanje prametara konekcije
                        //mijenja se tekst dugmeta za konekciju i prikazuje se poruka da je konekcija ostvarena
                        addrTextBox.Enabled = false;
                        portTextBox.Enabled = false;
                        usernameTextBox.Enabled = false;
                        keyTextBox.Enabled = false;
                        connectButton.Text = "Disconnect";
                        Log(SystemMsg("You are now connected"));
                        //System.Diagnostics.Debug.WriteLine(Encoding.UTF8.GetString(obj.pubKey));
                    }
                    else
                    {
                        //ako konekcija nije aktivna ukljucuju se kontrole za podesavanje prametara konekcije
                        //mijenja se tekst dugmeta za konekciju i prikazuje se poruka da je konekcija zavrsena
                        addrTextBox.Enabled = true;
                        portTextBox.Enabled = true;
                        usernameTextBox.Enabled = true;
                        keyTextBox.Enabled = true;
                        connectButton.Text = "Connect";
                        Log(SystemMsg("You are now disconnected"));
                    }
                });
            }
        }


        //metoda za asinhrono citanje podataka od servera
        private void Read(IAsyncResult result)
        {
            int bytes = 0;
            if (obj.client.Connected)
            {
                try
                {
                    bytes = obj.stream.EndRead(result);
                }
                catch (Exception ex)
                {
                    Log(ErrorMsg(ex.Message));
                }
            }
            if (bytes > 0)
            {

                //dodavanje kompozitnih podataka u obj.data
                obj.data.AppendFormat("{0}", Encoding.UTF8.GetString(obj.buffer, 0, bytes));
                try
                {
                    if (obj.stream.DataAvailable)
                    {

                        //nastavljanje citanja ako ima podataka
                        obj.stream.BeginRead(obj.buffer, 0, obj.buffer.Length, new AsyncCallback(Read), null);
                    }
                    else
                    {
                        //prikaz akumuliranih podataka i resetovanje StringBuilder-a
                        JavaScriptSerializer json = new JavaScriptSerializer();
                        //rjecnik za primljenje podatke koji se sastoji od kljuca i podataka
                        Dictionary<string, string> data = json.Deserialize<Dictionary<string, string>>(obj.data.ToString());

                        //primanje public key servera
                        if (data.ContainsKey("publicKey"))
                        {
                            receivedServerKey = data["publicKey"];
                            // dekodiranje i pamcenje kljuca
                            serverKey = Convert.FromBase64String(receivedServerKey);
                            //string decodedKeyString = BitConverter.ToString(serverKey);
                            //ispis u konzoli za potrebe dev faze, kasnije zakomentarisati
                            receivedServerIV = data["IV"];
                            // dekodiranje i pamcenje kljuca
                            serverIV = Convert.FromBase64String(receivedServerIV);
                            enkriptovanaPorukaServera = data["message"];

                            /*DIJAGNOSTIKA*/
                            System.Diagnostics.Debug.WriteLine(receivedServerIV);
                            System.Diagnostics.Debug.WriteLine(receivedServerKey);
                            System.Diagnostics.Debug.WriteLine("kljuc klijenta" + Convert.ToBase64String(klijentDK.PublicKey));
                            System.Diagnostics.Debug.WriteLine(json.Serialize(serverKey));
                            System.Diagnostics.Debug.WriteLine(json.Serialize(klijentDK));
                            /*************************/
                        }
                        Log(Dekriptor(Convert.FromBase64String(enkriptovanaPorukaServera)));
                        System.Diagnostics.Debug.WriteLine(Dekriptor(Convert.FromBase64String(enkriptovanaPorukaServera)));
                        obj.data.Clear();
                        obj.handle.Set();// Signal da su podaci primljeni
                    }
                }
                catch (Exception ex)
                {
                    obj.data.Clear();
                    Log(ErrorMsg(ex.Message));
                    obj.handle.Set();// Signal da se desila greska
                }
            }
            else
            {


                obj.client.Close(); // zatvaranje konekcije ako nema podataka
                obj.handle.Set(); // Signal da je konekcija zatvorena
            }
        }

        //metoda za autentifikaciju
        private void ReadAuth(IAsyncResult result)
        {
            int bytes = 0;
            if (obj.client.Connected)
            {
                try
                {
                    bytes = obj.stream.EndRead(result);
                }
                catch (Exception ex)
                {
                    Log(ErrorMsg(ex.Message));
                }
            }
            if (bytes > 0)
            {
                obj.data.AppendFormat("{0}", Encoding.UTF8.GetString(obj.buffer, 0, bytes));
                try
                {
                    if (obj.stream.DataAvailable)
                    {
                        obj.stream.BeginRead(obj.buffer, 0, obj.buffer.Length, new AsyncCallback(ReadAuth), null);
                    }
                    else
                    {
                        //serijalizacija podataka
                        JavaScriptSerializer json = new JavaScriptSerializer();
                        //rjecnik za primljenje podatke koji se sastoji od kljuca i podataka
                        Dictionary<string, string> data = json.Deserialize<Dictionary<string, string>>(obj.data.ToString());

                        //primanje public key servera
                        if (data.ContainsKey("publicKey"))
                        {
                            receivedServerKey = data["publicKey"];
                            // dekodiranje i pamcenje kljuca
                            serverKey = Convert.FromBase64String(receivedServerKey);
                            //string decodedKeyString = BitConverter.ToString(serverKey);
                            //ispis u konzoli za potrebe dev faze, kasnije zakomentarisati
                            receivedServerIV = data["IV"];
                            // dekodiranje i pamcenje kljuca
                            serverIV = Convert.FromBase64String(receivedServerIV);
                            /*DIJAGNOSTIKA*/
                            System.Diagnostics.Debug.WriteLine(receivedServerIV);
                            System.Diagnostics.Debug.WriteLine(receivedServerKey);
                            System.Diagnostics.Debug.WriteLine("kljuc klijenta" + Convert.ToBase64String(klijentDK.PublicKey));
                            System.Diagnostics.Debug.WriteLine(json.Serialize(serverKey));
                            System.Diagnostics.Debug.WriteLine(json.Serialize(klijentDK));
                            /**************************/
                        }



                        // provjera da li je konekcija uspjesna
                        if (data.ContainsKey("status") && data["status"].Equals("authorized"))
                        {


                            Connected(true);
                        }
                        obj.data.Clear();
                        obj.handle.Set(); // Signal da su podaci primljeni
                    }
                }
                catch (Exception ex)
                {
                    obj.data.Clear();
                    Log(ErrorMsg(ex.Message));
                    obj.handle.Set(); // Signal da se desila greska
                }
            }
            else
            {
                obj.client.Close();
                obj.handle.Set(); // Signal da je konekcija zatvorena
            }
        }


        //metoda za autorizaciju
        private bool Authorize()
        {
            //podrazumijevano da je neuspjesna
            bool success = false;
            //koristimo rjecnik za podatke <kljuc, vrijednost>
            Dictionary<string, string> data = new Dictionary<string, string>();
            //dodajemo podatke
            data.Add("username", obj.username);
            data.Add("key", obj.key);
            data.Add("pubKey", Convert.ToBase64String(klijentDK.PublicKey));
            data.Add("IV", Convert.ToBase64String(klijentDK.IV));
            JavaScriptSerializer json = new JavaScriptSerializer(); // kreiranje serijalizatora
            Send(json.Serialize(data)); // slanje serijalizovanih podataka

            //dok traje konekcija
            while (obj.client.Connected)
            {
                try
                {

                    //asinhrono citanje
                    obj.stream.BeginRead(obj.buffer, 0, obj.buffer.Length, new AsyncCallback(ReadAuth), null);
                    obj.handle.WaitOne(); // cekanje dok se podaci prime ili se desi greska
                    if (connected)
                    {
                        success = true; // ako je konekcija uspjesna
                        break; // izlazi iz while petlje
                    }
                }
                catch (Exception ex)
                {
                    Log(ErrorMsg(ex.Message)); // Poruka u slucaju greske
                }
            }
            if (!connected) // ako konekcija nije ostvarena
            {
                Log(SystemMsg("Unauthorized")); // Poruka da nije autorizovano
            }
            return success; // vracanje statusa
        }

        //metoda za ostvarivanje konekcije
        private void Connection(IPAddress ip, int port, string username, string key, byte[] pubKey)
        {
            try
            {
                //obj je tipa MyClient
                obj = new MyClient();
                //dodajemo potrebne podatke
                obj.username = username;
                obj.key = key;
                obj.pubKey = pubKey;
                //obj.IV = IV;
                obj.client = new TcpClient();
                obj.client.Connect(ip, port);
                obj.stream = obj.client.GetStream();
                obj.buffer = new byte[obj.client.ReceiveBufferSize];
                obj.data = new StringBuilder();
                obj.handle = new EventWaitHandle(false, EventResetMode.AutoReset);
                if (Authorize()) // ako je autorizacija uspjesna
                {
                    while (obj.client.Connected) // dok traje konekcija
                    {
                        try
                        {
                            //asinhrono citanje
                            obj.stream.BeginRead(obj.buffer, 0, obj.buffer.Length, new AsyncCallback(Read), null);
                            obj.handle.WaitOne(); // cekanje dok se podaci prime ili se desi greska
                        }
                        catch (Exception ex)
                        {
                            Log(ErrorMsg(ex.Message)); // Poruka u slucaju greske
                        }
                    }
                    obj.client.Close(); // zatvaranje konekcije
                    Connected(false); // status konekcije false oznacava da konekcija nije ostvarena
                }
            }
            catch (Exception ex)
            {
                Log(ErrorMsg(ex.Message));
            }
        }


        // event handler za event klik na ConnectButton
        private void ConnectButton_Click(object sender, EventArgs e)
        {
            if (connected)
            {
                obj.client.Close(); // ako je vec povezan ovaj klik prekida konekciju
            }

            // ako konekcija nije ostvarena
            else if (client == null || !client.IsAlive)
            {

                // kupi parametre za konekciju
                string address = addrTextBox.Text.Trim();
                string number = portTextBox.Text.Trim();
                string username = usernameTextBox.Text.Trim();
                bool error = false;
                IPAddress ip = null;
                if (address.Length < 1) // ako ip adresa ne ispunjava uslov duzine
                {
                    error = true; // greska je true
                    Log(SystemMsg("Address is required")); // Poruka da je doslo do greske
                }
                else
                {
                    try
                    {
                        ip = Dns.Resolve(address).AddressList[0]; // DNS resolve sa DNS serverom na osnovu unijete IP
                    }
                    catch
                    {
                        error = true; // greska
                        Log(SystemMsg("Address is not valid")); // Poruka da adresa nije ispravna
                    }
                }
                // promjenjiva port je postavlja na -1 kao podrazumijevana vrednost.
                // ovo se radi za rešavanje situacija u kojima broj porta nedostaje ili je nevažeći.
                int port = -1;

                // ako je  broj porta izostavljen ili neispravan
                if (number.Length < 1)
                {
                    error = true; // greska
                    Log(SystemMsg("Port number is required")); // poruka da je potreban broj porta
                }

                // Metoda int.TryParse se koristi za pokušaj raščlanjivanja ulaznog niza 'number' u cjelobrojnu vrijednost 'port'.
                // Ako je raščlanjivanje uspješno, vrijednost 'port' će biti postavljena na raščlanjenu cjelobrojnu vrijednost.
                // Ako raščlanjivanje nije uspjelo, izlazni parametar 'port' će biti postavljen na podrazumijevanu vrijednost 0.
                else if (!int.TryParse(number, out port))
                {
                    error = true; // greska
                    Log(SystemMsg("Port number is not valid")); // poruka da je broj porta neispravan
                }

                // ako port nije u validnom opsegu
                else if (port < 0 || port > 65535)
                {
                    error = true; // greska
                    Log(SystemMsg("Port number is out of range")); // poruka da je broj porta izvan opsega
                }

                // ako je username prazan
                if (username.Length < 1)
                {
                    error = true; // greska
                    Log(SystemMsg("Username is required")); // poruka da je potrebno unijeti username
                }

                // ako nema greske
                if (!error)
                {
                    // kljuc za povezivanje je opcion
                    // kreira se novi Thread za konekciju
                    client = new Thread(() => Connection(ip, port, username, keyTextBox.Text, klijentDK.PublicKey))
                    {
                        IsBackground = true
                    };
                    client.Start(); // pokrece se konekcija
                }
            }
        }


        // metoda za pisanje podataka serveru
        private void Write(IAsyncResult result)
        {
            // ako je ostvarena konekcija
            if (obj.client.Connected)
            {
                try
                {
                    // Metoda 'EndWrite' se poziva da finalizuje operaciju asinhronog pisanja koju pokreće 'BeginVrite'.
                    // Čeka da se operacija pisanja završi i izbacuje sve izuzetke koji su se desili tokom pisanja.
                    obj.stream.EndWrite(result);
                }
                catch (Exception ex)
                {
                    Log(ErrorMsg(ex.Message)); // Prikazuje se greska
                }
            }
        }


        // metoda za asinhrono pisanje
        private void BeginWrite(string msg)
        {
            // pretvara ulazni string 'msg' u niz bajtova
            byte[] buffer = Encoding.UTF8.GetBytes(msg);

            // ako je klijent povezan
            if (obj.client.Connected)
            {
                try
                {
                    // Metoda 'BeginVrite' se poziva da pokrene operaciju asinhronog pisanja.
                    // Zapisuje podatke iz bafera u mrežni tok.
                    // Metoda 'Write' će biti pozvana kada se operacija pisanja završi ili dođe do greške.
                    obj.stream.BeginWrite(buffer, 0, buffer.Length, new AsyncCallback(Write), null);
                }
                catch (Exception ex)
                {

                    Log(ErrorMsg(ex.Message)); // ako je doslo do greske prikazuje se poruka
                }
            }
        }

        // metoda za asinhrono pisanje enkriptovanih poruka
        private void BeginWriteEncrypted(byte[] poruka)
        {
            // pretvara ulazni string 'msg' u niz bajtova
            byte[] buffer = poruka;

            // ako je klijent povezan
            if (obj.client.Connected)
            {
                try
                {
                    // Metoda 'BeginVrite' se poziva da pokrene operaciju asinhronog pisanja.
                    // Zapisuje podatke iz bafera u mrežni tok.
                    // Metoda 'Write' će biti pozvana kada se operacija pisanja završi ili dođe do greške.
                    obj.stream.BeginWrite(buffer, 0, buffer.Length, new AsyncCallback(Write), null);
                }
                catch (Exception ex)
                {

                    Log(ErrorMsg(ex.Message)); // ako je doslo do greske prikazuje se poruka
                }
            }
        }

        // metoda za slanje poruka serveru
        private void Send(string msg)
        {
            //provjeravamo da li je prethodno slanje zavrseno ili je null(nije ni pocelo)
            if (send == null || send.IsCompleted)
            {
                // Ako je prethodna operacija slanja zavrsena ili je null,
                // zapocinje novi zadatak koristeci Task.Factory.StartNev() koji poziva metodu BeginWrite.
                send = Task.Factory.StartNew(() => BeginWrite(msg));
            }
            else
            {
                // Ako je prethodna operacija slanja jos uvek u toku (nije zavrsena),
                //  nastavak uz pomoc ContinueWith() koji poziva metodu BeginWrite.
                send.ContinueWith(antecendent => BeginWrite(msg));
            }
        }

        // metoda za slanje enkriptovanih poruka serveru
        private void SendEncrypted(byte[] poruka)
        {
            //provjeravamo da li je prethodno slanje zavrseno ili je null(nije ni pocelo)
            if (send == null || send.IsCompleted)
            {
                // Ako je prethodna operacija slanja zavrsena ili je null,
                // zapocinje novi zadatak koristeci Task.Factory.StartNev() koji poziva metodu BeginWrite.
                send = Task.Factory.StartNew(() => BeginWriteEncrypted(poruka));
            }
            else
            {
                // Ako je prethodna operacija slanja jos uvek u toku (nije zavrsena),
                //  nastavak uz pomoc ContinueWith() koji poziva metodu BeginWrite.
                send.ContinueWith(antecendent => BeginWriteEncrypted(poruka));
            }
        }

        // metoda 
        private void SendTextBox_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.KeyCode == Keys.Enter)
            {
                e.Handled = true;
                e.SuppressKeyPress = true;
                if (sendTextBox.Text.Length > 0)
                {

                    // ovdje se poziva enkripcija i enkriptuje se poruka koristenjem klijentDK.Encrypt metode
                    byte[] secretMessage = klijentDK.Encrypt(serverKey, sendTextBox.Text);
                    System.Diagnostics.Debug.WriteLine(Convert.ToBase64String(secretMessage));

                    // konvertujemo enkriptovanu poruku iz niza bajtova u string
                    // ova se poruka salje
                    string msg = Convert.ToBase64String(secretMessage);// + (Encoding.UTF8.GetString(klijentDK.PublicKey));


                    //System.Diagnostics.Debug.WriteLine(Encoding.UTF8.GetString(klijentDK.PublicKey));
                    // Prikazujemo poslatu poruku u Client prozoru
                    Log(string.Format("{0} (You): {1}", obj.username, sendTextBox.Text));
                    // Cistimo sadrzaj sendTextBox
                    sendTextBox.Clear();
                    if (connected) // ako je konektovan
                    {
                        // saljemo serijaliyovanu poruku serveru
                        Send(Poruka(secretMessage));

                    }
                }
            }
        }

        //formatiranje stringa
        static string RemoveNonAlphaNumeric(string input)
        {
            // Regex sablon ya sredjivanje stringa
            string pattern = @"[^\p{L}0-9\s\p{P}đžšćč]+";

            // Uklanjanje karaktera koristenjem Regex.Replace
            string result = Regex.Replace(input, pattern, "");
            return result;
        }

        // kada se forma zatvara
        private void Client_FormClosing(object sender, FormClosingEventArgs e)
        {
            exit = true;
            if (connected) // ako je konekcija aktivna
            {
                obj.client.Close(); // zatvaramo konekciju
            }
        }

        // klikom na dugme Clear
        private void ClearButton_Click(object sender, EventArgs e)
        {
            Log(); // cisti se sendTextBox pozivanjem funkcije Log()
        }

        // listener za checkbox kojim se bira da li se prikazuje kljuc za povezivanje
        private void CheckBox_CheckedChanged(object sender, EventArgs e)
        {
            if (keyTextBox.PasswordChar == '*') // ako je PasswordChar == '*' to znaci da je skriveno
            {
                keyTextBox.PasswordChar = '\0'; // uklanja se maska
            }

            // ako nije postavljena maska
            else
            {
                keyTextBox.PasswordChar = '*'; // postavlja masku *
            }
        }


        //funkcija za dekripciju primljenih poruka
        private string Dekriptor(byte[] encrypted)
        {



            string dekriptovanaPoruka = klijentDK.Decrypt(serverKey, encrypted, serverIV) + Environment.NewLine;
            return dekriptovanaPoruka;
        }


        //priprema poruke za slanje sa svim potrebnim podacima
        private string Poruka(byte[] enkriptovana)
        {
            Dictionary<string, string> servMsg = new Dictionary<string, string>();
            servMsg.Add("publicKey", Convert.ToBase64String(klijentDK.PublicKey));
            servMsg.Add("IV", Convert.ToBase64String(klijentDK.IV));
            servMsg.Add("message", Convert.ToBase64String(enkriptovana));
            JavaScriptSerializer jsonServ = new JavaScriptSerializer();

            return (jsonServ.Serialize(servMsg));
        }


    }
}
