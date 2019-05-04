using System;
using System.IO;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Windows;
using System.Windows.Input;

namespace RSA
{
    /// <summary>
    /// Logika interakcji dla klasy MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        #region Properties
        private CspParameters cspp;
        /// <summary>
        /// Instancaj generatora klucza oraz funkcji szyfrujących.
        /// </summary>
        private RSACryptoServiceProvider RSAencrypt;
        /// <summary>
        /// Instancaj generatora klucza oraz funkcji deszyfrujących.
        /// </summary>
        private RSACryptoServiceProvider RSAdecrypt;

        /// <summary>
        /// Wiadomość do zaszyfrowania w postaci bitowej.
        /// </summary>
        private byte[] dataToEncrypt;
        /// <summary>
        /// Zaszyfrowana wiadomość w postaci bitowej.
        /// </summary>
        private byte[] encryptedData;
        /// <summary>
        /// Odszyfrowana wiadomość w postaci bitowej.
        /// </summary>
        private byte[] decryptedData;

        byte[] encryptedMessageFromFileInBytes;

        const string KEY_NAME = "Key01";
        const string KEY_PATH = @"G:\klucze.txt";
        const string MESSAGE_TO_ENCRYPT_PATH = @"G:\test.txt";
        const string ENCRYPTED_MESSAGE_PATH = @"G:\zaszyfrowana.txt";
        const string DECRYPTED_MESSAGE_PATH = @"G:\odszyfrowana.txt";

        /// <summary>
        /// Pobrana wersja wiadomości zaszyfrowanej z pliku. 
        /// </summary>
        private string encryptedMessageFromFile;
        /// <summary>
        /// Zaimportowany klucz.
        /// </summary>
        private string importedKey;
        /// <summary>
        /// Flaga wskazująca czy zostały zaimportowane z pliku klucze.
        /// </summary>
        private bool isKeyImported = false;
        /// <summary>
        /// Flaga wskazująca czy wersja windowsa jest niższ niż Windows 2000.
        /// </summary>
        private bool windowsVersionLowerThen2000;
        #endregion

        public MainWindow()
        {
            InitializeComponent();

            //Sprawdzam wersję windowsa, jest to potrzebne do szyfrowania w bibliotece z której korzystam.
            this.windowsVersionLowerThen2000 = IsXpOrHigher();

            this.cspp = new CspParameters();
            this.cspp.KeyContainerName = KEY_NAME;
        }

        #region IsXpOrHigher
        /// <summary>
        /// Sprawdza wersję windowsa na którym została włączona aplikacja.
        /// Jeżeli jest to wersja powyżej 5.0 jest to wersja od windows.XP.
        /// Jeżeli jest niższa niż i równa 5.0 jest to wersja 2000 i niższa.
        /// Wersję od XP obsługują Optimal Asymmetric Encryption Padding (OAEP), 
        /// potrzebną do deszyfrowania przy pomocy RSA.
        /// </summary>
        /// <returns>Jeżeli system jest w wersji powyżej XP to zwraca false. Jeżeli poniżej wersji XP to zwraca true.</returns>
        private bool IsXpOrHigher()
        {
            var os = Environment.OSVersion;
            if (os.Version.Major > 5 || (os.Version.Major == 5 && os.Version.Minor > 0)) return false;
            else return true;
        }
        #endregion

        #region TopBarContent_MouseDown
        /// <summary>
        /// Moving whole application window after drag top bar of application, when the left button was clicked.
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void TopBarContent_MouseDown(object sender, MouseButtonEventArgs e)
        {
            if (e.ChangedButton == MouseButton.Left)
                this.DragMove();
        }
        #endregion
        #region Minimize_Click
        /// <summary>
        /// Minimalizing size of the application.
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void Minimize_Click(object sender, RoutedEventArgs e)
        {
            this.WindowState = WindowState.Minimized;
        }
        #endregion
        #region Exit_Click
        /// <summary>
        /// Action after click in top bar right corner button.
        /// Closing application.
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void Exit_Click(object sender, RoutedEventArgs e)
        {
            this.Close();
        }
        #endregion
            
        #region buttonCreateAsmKeys_Click
        private void buttonCreateAsmKeys_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                this.RSAencrypt = new RSACryptoServiceProvider(cspp);
                this.tbCreateAsmKey.Text = "Twój klucz to: " + this.RSAencrypt.ToXmlString(false);
            }
            catch (CryptographicException) { this.tbCreateAsmKey.Text = "Wystąpił błąd przy tworzeniu kluczy."; };
        }
        #endregion
        #region buttonChoseFileToEncrypt_Click
        private void buttonChoseFileToEncrypt_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                this.dataToEncrypt = File.ReadAllBytes(MESSAGE_TO_ENCRYPT_PATH);
                this.tbChosenMessage.Text = File.ReadAllText(MESSAGE_TO_ENCRYPT_PATH);
            }
            catch (ArgumentNullException) { this.tbChosenMessage.Text = "Nie wybrano żadnego pliku."; }
            catch (PathTooLongException) { this.tbChosenMessage.Text = "Ścieżka dostępu jest za długa."; }
            catch (DirectoryNotFoundException) { this.tbChosenMessage.Text = "Nie ma takiego pliku lub jego część jest niemożliwa do odczytania."; }
            catch (UnauthorizedAccessException) { this.tbChosenMessage.Text = "Brak dostępu do pliku."; }
            catch (FileNotFoundException) { this.tbChosenMessage.Text = "Nie znaleziono pliku o takiej nazwie.";  }
            catch (NotSupportedException) { this.tbChosenMessage.Text = "Nie można odczytać pliku tego formatu."; }
            catch (IOException) { this.tbChosenMessage.Text = "Plik jest używany przez inną aplikację."; }
            catch (SecurityException) { this.tbChosenMessage.Text = "Plik jest nieosiągalny."; }
        }
        #endregion
        #region buttonEncryptFile_Click
        private void buttonEncryptFile_Click(object sender, RoutedEventArgs e)
        {
            this.RSAencrypt.PersistKeyInCsp = true; //Zawarcie klucza w wiadomości.

            try
            {
                this.encryptedData = this.RSAencrypt.Encrypt(this.dataToEncrypt, this.windowsVersionLowerThen2000);//Szyfrowanie wiadomości.
            }
            catch (CryptographicException) { this.tbEncryptMessage.Text = "Szyfrowanie wiadmości nie powidoło się. Upewnij się że zostały wygenerowane."; }
            catch (ArgumentNullException) { this.tbEncryptMessage.Text = "Musisz wybrać plik do odszyfrowania."; }

            try
            {
                if (this.decryptedData == null) this.tbEncryptMessage.Text = "Wiadomość jest za długa, zaszyfrować można tylko blok 128 bajtowy.";
                else if (this.encryptedData.Length > 0)
                {
                    File.WriteAllBytes(ENCRYPTED_MESSAGE_PATH, this.encryptedData);
                    this.tbEncryptMessage.Text = "Wiadomość została zapisana w pliku: " + ENCRYPTED_MESSAGE_PATH;
                }
                else if (this.encryptedData.Length == 0) this.tbEncryptMessage.Text = "Wiadomość jest za krótka.";
            }
            catch (ArgumentNullException) { this.tbEncryptMessage.Text = "Nie wybrano żadnego pliku."; }
            catch (PathTooLongException) { this.tbEncryptMessage.Text = "Ścieżka dostępu jest za długa."; }
            catch (DirectoryNotFoundException) { this.tbEncryptMessage.Text = "Błąd zapsiu, plik został uszkodzony w trakcie zapisu."; }
            catch (UnauthorizedAccessException) { this.tbEncryptMessage.Text = "Brak dostępu."; }
            catch (NotSupportedException) { this.tbEncryptMessage.Text = "Nie można zapisać pliku w tym formacie."; }
            catch (SecurityException) { this.tbEncryptMessage.Text = "Nie można zapisać pliku ze względów bezpieczeństwa.";  }
        }
        #endregion
        #region buttonChoseDecryptFile_Click
        private void buttonChoseDecryptFile_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                this.encryptedMessageFromFileInBytes = File.ReadAllBytes(ENCRYPTED_MESSAGE_PATH);
                this.encryptedMessageFromFile = File.ReadAllText(ENCRYPTED_MESSAGE_PATH); //Odczytanie zaszyfrowanej wiadomości w UTF8
                this.tbEncryptedChosenMessage.Text = encryptedMessageFromFile;
            }
            catch (ArgumentNullException) { this.tbEncryptedChosenMessage.Text = "Nie wybrano żadnego pliku."; }
            catch (PathTooLongException) { this.tbEncryptedChosenMessage.Text = "Ścieżka dostępu jest za długa."; }
            catch (DirectoryNotFoundException) { this.tbEncryptedChosenMessage.Text = "Nie ma takiego pliku lub jego część jest niemożliwa do odczytania."; }
            catch (UnauthorizedAccessException) { this.tbEncryptedChosenMessage.Text = "Brak dostępu do pliku."; }
            catch (FileNotFoundException) { this.tbEncryptedChosenMessage.Text = "Nie znaleziono pliku o takiej nazwie."; }
            catch (NotSupportedException) { this.tbEncryptedChosenMessage.Text = "Nie można odczytać pliku tego formatu."; }
            catch (IOException) { this.tbChosenMessage.Text = "Plik jest używany przez inną aplikację."; }
            catch (SecurityException) { this.tbChosenMessage.Text = "Plik jest nieosiągalny."; }
        }
        #endregion
        #region buttonDecryptFile_Click
        private void buttonDecryptFile_Click(object sender, RoutedEventArgs e)
        {
            CspParameters csp2 = new CspParameters();
            csp2.KeyContainerName = KEY_NAME;

            this.RSAdecrypt = new RSACryptoServiceProvider(csp2);
            this.RSAdecrypt.PersistKeyInCsp = true;

            if (this.isKeyImported)
               this.RSAdecrypt.FromXmlString(this.importedKey);

           try 
            {
                //Odszyfrowanie wcześniej zaimportowanej wiadomości.
                this.decryptedData = this.RSAdecrypt.Decrypt(this.encryptedMessageFromFileInBytes, this.windowsVersionLowerThen2000);
                this.tbDecryptMessage.Text = Encoding.UTF8.GetString(this.decryptedData);

                File.WriteAllText(DECRYPTED_MESSAGE_PATH, Encoding.UTF8.GetString(this.decryptedData));
            }
            catch (CryptographicException) {this.tbDecryptMessage.Text = "Odszyfrowanie wiadmości nie powidoło się. Upewnij się że zostały wygenerowane klucze lub został zaimportowany prywatny klucz.";
            }
            catch (ArgumentNullException) { this.tbDecryptMessage.Text = "Musisz wybrać plik do odszyfrowania."; }
        }
        #endregion
        #region buttonExportPublicKey_Click
        private void buttonExportPublicKey_Click(object sender, RoutedEventArgs e)
        {
            try
            {   
                //Zapisywanie tylko publicznego klucza do pliku - jeżeli false.
                //Jeżeli true - to wysyła publiczny i prywatny.
                File.WriteAllText(KEY_PATH, RSAencrypt.ToXmlString(this.cbPublicAndPrivateKeyExport.IsChecked == true ? true : false), new UTF8Encoding());
                this.tbExportPrivateKey.Text = "Klucz został zapisany w " + KEY_PATH + ".";
            }
            catch (ArgumentNullException) { this.tbExportPrivateKey.Text = "Nie wybrano żadnego pliku."; }
            catch (PathTooLongException) { this.tbExportPrivateKey.Text = "Ścieżka dostępu jest za długa."; }
            catch (DirectoryNotFoundException) { this.tbExportPrivateKey.Text = "Błąd zapsiu, plik został uszkodzony w trakcie zapisu."; }
            catch (UnauthorizedAccessException) { this.tbExportPrivateKey.Text = "Brak dostępu."; }
            catch (NotSupportedException) { this.tbExportPrivateKey.Text = "Nie można zapisać pliku w tym formacie."; }
            catch (SecurityException) { this.tbExportPrivateKey.Text = "Nie można zapisać pliku ze względów bezpieczeństwa."; }
        }
        #endregion
        #region buttonImportKey_Click
        private void buttonImportKey_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                this.importedKey = File.ReadAllText(KEY_PATH);
                this.tbImportKey.Text = "Klucz został zaimportowany.";
                this.isKeyImported = true;
            }
            catch (ArgumentNullException) { this.tbImportKey.Text = "Nie wybrano żadnego pliku."; }
            catch (PathTooLongException) { this.tbImportKey.Text = "Ścieżka dostępu jest za długa."; }
            catch (DirectoryNotFoundException) { this.tbImportKey.Text = "Nie ma takiego pliku lub jego część jest niemożliwa do odczytania."; }
            catch (UnauthorizedAccessException) { this.tbImportKey.Text = "Brak dostępu do pliku."; }
            catch (FileNotFoundException) { this.tbImportKey.Text = "Nie znaleziono pliku o takiej nazwie."; }
            catch (NotSupportedException) { this.tbImportKey.Text = "Nie można odczytać pliku tego formatu."; }
            catch (IOException) { this.tbChosenMessage.Text = "Plik jest używany przez inną aplikację."; }
            catch (SecurityException) { this.tbChosenMessage.Text = "Plik jest nieosiągalny."; }
        }
        #endregion  

        private void DoEverything()
        {
            try
            {
                //byte[] dataToEncrypt = Encoding.UTF8.GetBytes(File.ReadAllText(stringEncryptedData));
                byte[] encryptedData;
                byte[] decryptedData;

                //Create a new instance of RSACryptoServiceProvider to generate
                //public and private key data.
                using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider(cspp))
                {
                    RSA.PersistKeyInCsp = false; //Zawarcie klucza w wiadomości.
                    encryptedData = RSA.Encrypt(dataToEncrypt, false);// Szyfrowanie wiadomości.

                    string encryptedMessage = Encoding.UTF8.GetString(encryptedData);//Konwersja bajtów na kod UTF8

                    File.WriteAllBytes(ENCRYPTED_MESSAGE_PATH, encryptedData);
                    File.WriteAllText(KEY_PATH, RSA.ToXmlString(false), new UTF8Encoding());//Zapisywanie publicznego klucza do pliku.

                    //Console.WriteLine("Wiadomość do zaszyfrowania: {0}", stringEncryptedData);

                    Console.WriteLine("Wiadomość przerobiona na byte: "); foreach (byte b in dataToEncrypt) Console.Write("{0} ", b);
                    Console.WriteLine("\n");

                    Console.WriteLine("Wiadomość zaszyfrowana w byte: "); foreach (byte b in encryptedData) Console.Write("{0} ", b);
                    Console.WriteLine("\n");

                    Console.WriteLine("Wiadomość zaszyfrowna i przerobiona na UTF8:\n {0} ", encryptedMessage);

                    byte[] encryptedMessageFromFileInBytes = File.ReadAllBytes(ENCRYPTED_MESSAGE_PATH);

                    string encryptedMessageFromFile = File.ReadAllText(ENCRYPTED_MESSAGE_PATH);//Odczytanie zaszyfrowanej wiadomości w UTF8Encoding
                    Console.WriteLine("W pliku:\n {0} \n", encryptedMessageFromFile);

                    //Test zgodności UTF8 tych z pliku i tych co są w "APLIKACJI"
                    Console.WriteLine("Test zgodności stringów w UTF8: {0} \n", encryptedMessage == encryptedMessageFromFile ? true : false);

                    //Test zgodności byte tych z wiadomością zaszyfrowaną na początku i z tą odczytaną z pliku.
                    {
                        int correctNummberOfSignsInFile = 0;
                        int incorrectNummberOfSignsInFile = 0;
                        for (int i = 0; i < encryptedMessage.Length; i++)
                        {
                            if (encryptedData[i] == encryptedMessageFromFileInBytes[i]) correctNummberOfSignsInFile++;
                            else incorrectNummberOfSignsInFile++;
                        }

                        Console.WriteLine("Zgodna ilość znaków: {0}, Niezgodna ilość znaków: {1} \n", correctNummberOfSignsInFile, incorrectNummberOfSignsInFile);
                    }

                    //Wyświetlenie wyników konwersji bitów na UTF8
                    Console.Write("Z pliku, z UTF8 na byte: "); foreach (byte b in encryptedMessageFromFileInBytes) Console.Write("{0} ", b);
                    Console.WriteLine("\n");

                    //Pobieranie klucza z pliku.
                    string klucz = File.ReadAllText(KEY_PATH);

                    CspParameters cspp2 = new CspParameters();
                    cspp2.KeyContainerName = KEY_NAME;

                    //Tworzenie nowej instancji RSA i pobieranie klucza z pliku.
                    RSACryptoServiceProvider RSA2 = new RSACryptoServiceProvider(cspp2);
                    RSA2.PersistKeyInCsp = true;
                    //RSA2.FromXmlString(klucz);

                    decryptedData = RSA2.Decrypt(encryptedMessageFromFileInBytes, false);
                    Console.WriteLine("Odszyfrowana wiadomość: " + Encoding.UTF8.GetString(decryptedData));
                    File.WriteAllText(DECRYPTED_MESSAGE_PATH, Encoding.UTF8.GetString(decryptedData));
                }
            }
            catch (ArgumentNullException)
            {
                Console.WriteLine("Encryption failed.");
            }
        }
    }
}

