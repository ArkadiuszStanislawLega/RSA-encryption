using Microsoft.Win32;
using System;
using System.IO;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;

namespace RSA
{
    /// <summary>
    /// Logika interakcji dla klasy MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        #region Properties
        const string KEY_NAME = "Key01";

        #region EXCETPION_MESSAGES
        const string EXCEPTION_MESSAGE_UNAUTORIZED_ACCESS = "Do poprawnego działania aplikacji, należy przenieść plik wykonywalny przenieść w miejsce które nie wymaga autoryzacji administratora.";
        const string EXCETPION_MESSAGE_NOT_SUPPORTED = "Nie można zapisać pliku w tym formacie.";
        const string EXCEPTION_MESSAGE_ARGUMENT_NULL = "Nie wybrano żadnego pliku.";
        const string EXCEPTION_MESSAGE_PATH_TOO_LONG = "Ścieżka dostępu jest za długa.";
        const string EXCEPTION_MESSAGE_DIRECTORY_NOT_FOUND = "Nie znaleziono pliku pod tą ścieżką dostępu.";
        const string EXCEPTION_MESSAGE_SECURITY = "Nie można zapisać pliku ze względów bezpieczeństwa.";
        const string EXCEPTION_MESSAGE_FILE_NOT_FOUND = "Nie znaleziono pliku.";
        const string EXCEPTION_MESSAGE_IO = "Błąd. Plik jest prawdopodnie używany przez inną aplikację.";
        const string EXCEPTION_MESSAGE_ARGUMENT = "Nie wybrano żadnego pliku.";
        #endregion

        /// <summary>
        /// Instancja przechowująca parametry kluczy.
        /// </summary>
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
        /// <summary>
        /// Wiadomość zaszyfrowana odczytana z pliku.
        /// </summary>
        private byte[] encryptedMessageFromFileInBytes;

        /// <summary>
        /// Ścieżka dostępu do pliku z wiadomością zaszyfrowaną która będzie deszyfrowana.
        /// </summary>
        private string decryptedMessagePath = "";
        /// <summary>
        /// Ścieżka dostępu do pliku z wiadomścią która będzie szyfrowana.
        /// </summary>
        private string messageToEncryptPath = "";
        /// <summary>
        /// Ścieżka dostępu do miejsca w którym będzie zapisany plik z zaszyfrowaną wiadomością.
        /// </summary>
        private string encryptedMessagePath = "";
        /// <summary>
        /// Ścieżka dostępu do pliku w którym będą przechowywane klucze.
        /// </summary>
        private string keysPath = "";
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

        #region Basic Constructor
        public MainWindow()
        {
            InitializeComponent();

            //Sprawdzam wersję windowsa, jest to potrzebne do szyfrowania w bibliotece z której korzystam.
            this.windowsVersionLowerThen2000 = IsXpOrHigher();

            this.cspp = new CspParameters();
            this.cspp.KeyContainerName = KEY_NAME;
            try
            {
                this.decryptedMessagePath = Directory.GetCurrentDirectory() + @"\odszyfrowana wiadomosc.txt";
                this.keysPath = Directory.GetCurrentDirectory() + @"\klucze.txt";
            }
            catch (UnauthorizedAccessException)
            {
                MessageBox.Show("Do poprawnego działania aplikacji, należy przenieść plik wykonywalny przenieść w miejsce które nie wymaga autoryzacji administratora.");
            }
            catch (NotSupportedException) { }
        }
        #endregion

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
        /// <summary>
        /// Akcja po wciśnięciu przycisku "Tworzenie kluczy asymetrycznych".
        /// Powstaje nowa instancja RSACryptoServiceProvider.
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
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
        /// <summary>
        /// Akcja po wciśnięciu przycisku "Wybierz plik do zaszyfrowania".
        /// Otwiera się okno z wyborem pliku do zaszyfrowania, przyjmuję tylko pliki txt.
        /// Wiadomość nie może być większa niż 128 bajtów.
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void buttonChoseFileToEncrypt_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                OpenFileDialog openFileDialog = new OpenFileDialog();
                openFileDialog.InitialDirectory = Directory.GetCurrentDirectory();
                openFileDialog.Filter = "txt files (*.txt)|*.txt";
                openFileDialog.RestoreDirectory = true;

                if (openFileDialog.ShowDialog() == true) this.messageToEncryptPath = openFileDialog.FileName;

                this.dataToEncrypt = File.ReadAllBytes(messageToEncryptPath);
                this.tbChosenMessage.Text = File.ReadAllText(messageToEncryptPath);
            }
            catch (ArgumentNullException) { this.tbChosenMessage.Text = EXCEPTION_MESSAGE_ARGUMENT_NULL; }
            catch (PathTooLongException) { this.tbChosenMessage.Text = EXCEPTION_MESSAGE_PATH_TOO_LONG; }
            catch (DirectoryNotFoundException) { this.tbChosenMessage.Text = EXCEPTION_MESSAGE_DIRECTORY_NOT_FOUND; }
            catch (UnauthorizedAccessException) { this.tbChosenMessage.Text = EXCEPTION_MESSAGE_UNAUTORIZED_ACCESS; }
            catch (FileNotFoundException) { this.tbChosenMessage.Text = EXCEPTION_MESSAGE_FILE_NOT_FOUND;  }
            catch (NotSupportedException) { this.tbChosenMessage.Text = EXCETPION_MESSAGE_NOT_SUPPORTED; }
            catch (IOException) { this.tbChosenMessage.Text = EXCEPTION_MESSAGE_IO; }
            catch (SecurityException) { this.tbChosenMessage.Text = EXCEPTION_MESSAGE_SECURITY; }
            catch (ArgumentException) { this.tbChosenMessage.Text = EXCEPTION_MESSAGE_ARGUMENT; }
        }
        #endregion
        #region buttonEncryptFile_Click
        /// <summary>
        /// Akcja po wciśnięciu przycisku "Zaszyfruj".
        /// Wiadomość jest szyfrowana i zapisywana na dysku w mijescu aktualnego położenia pliku exe aplikacji.
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void buttonEncryptFile_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                this.encryptedData = this.RSAencrypt.Encrypt(this.dataToEncrypt, this.windowsVersionLowerThen2000);//Szyfrowanie wiadomości.
            }
            catch (CryptographicException) { this.tbEncryptMessage.Text = "Szyfrowanie wiadmości nie powidoło się. Upewnij się że zostały wygenerowane klucze."; }
            catch (ArgumentNullException) { this.tbEncryptMessage.Text = "Musisz wybrać plik do odszyfrowania."; }

            try
            {
                if (this.encryptedData == null) this.tbEncryptMessage.Text = "Wiadomość jest za długa, zaszyfrować można tylko blok 128 bajtowy. Ten plik jest: " + this.dataToEncrypt.Length + " bajtowy.";
                else if (this.encryptedData.Length > 0)
                {
                    File.WriteAllBytes(encryptedMessagePath, this.encryptedData);
                    this.tbEncryptMessage.Text = "Wiadomość została zapisana w pliku: " + this.encryptedMessagePath;
                }
                else if (this.encryptedData.Length == 0) this.tbEncryptMessage.Text = "Wiadomość jest za krótka.";
            }
            catch (ArgumentNullException) { this.tbEncryptMessage.Text = EXCEPTION_MESSAGE_ARGUMENT_NULL; }
            catch (PathTooLongException) { this.tbEncryptMessage.Text = EXCEPTION_MESSAGE_PATH_TOO_LONG; }
            catch (DirectoryNotFoundException) { this.tbEncryptMessage.Text = EXCEPTION_MESSAGE_DIRECTORY_NOT_FOUND; }
            catch (UnauthorizedAccessException) { this.tbEncryptMessage.Text = EXCEPTION_MESSAGE_UNAUTORIZED_ACCESS; }
            catch (NotSupportedException) { this.tbEncryptMessage.Text = EXCETPION_MESSAGE_NOT_SUPPORTED; }
            catch (SecurityException) { this.tbEncryptMessage.Text = EXCEPTION_MESSAGE_SECURITY;  }
        }
        #endregion
        #region buttonChoseDecryptFile_Click
        /// <summary>
        /// Akcja po wciśnięciu przycisku "Wybierz plik do odszyfrowania".
        /// Otwiera się okno dialogowe z wyborem pliku do odszyfrowania, otwiera tylko pliki txt.
        /// Dane z pliku są przetrzymwane w <seealso cref="encryptedMessageFromFileInBytes"/> w postaci tablicy byte.
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void buttonChoseDecryptFile_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                OpenFileDialog openFileDialog = new OpenFileDialog();
                openFileDialog.InitialDirectory = Directory.GetCurrentDirectory();
                openFileDialog.Filter = "txt files (*.txt)|*.txt";
                openFileDialog.RestoreDirectory = true;

                if (openFileDialog.ShowDialog() == true) this.encryptedMessagePath = openFileDialog.FileName;

                this.encryptedMessageFromFileInBytes = File.ReadAllBytes(encryptedMessagePath);
                this.encryptedMessageFromFile = File.ReadAllText(encryptedMessagePath); //Odczytanie zaszyfrowanej wiadomości w UTF8
                this.tbEncryptedChosenMessage.Text = encryptedMessageFromFile;
            }
            catch (ArgumentNullException) { this.tbChosenMessage.Text = EXCEPTION_MESSAGE_ARGUMENT_NULL; }
            catch (PathTooLongException) { this.tbChosenMessage.Text = EXCEPTION_MESSAGE_PATH_TOO_LONG; }
            catch (DirectoryNotFoundException) { this.tbChosenMessage.Text = EXCEPTION_MESSAGE_DIRECTORY_NOT_FOUND; }
            catch (UnauthorizedAccessException) { this.tbChosenMessage.Text = EXCEPTION_MESSAGE_UNAUTORIZED_ACCESS; }
            catch (FileNotFoundException) { this.tbChosenMessage.Text = EXCEPTION_MESSAGE_FILE_NOT_FOUND; }
            catch (NotSupportedException) { this.tbChosenMessage.Text = EXCETPION_MESSAGE_NOT_SUPPORTED; }
            catch (IOException) { this.tbChosenMessage.Text = EXCEPTION_MESSAGE_IO; }
            catch (SecurityException) { this.tbChosenMessage.Text = EXCEPTION_MESSAGE_SECURITY; }
            catch (ArgumentException) { this.tbChosenMessage.Text = EXCEPTION_MESSAGE_ARGUMENT; }
        }
        #endregion
        #region buttonDecryptFile_Click
        /// <summary>
        /// Akcja po wciśnięciu przycisku "Odszyfruj".
        /// Odszyfrowuje wcześniej pobraną wiadomość, wyświetla zawartość tej wiadomości
        /// oraz zapisuje je w katalogu w którym znajduję się aplikacja. 
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
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

                try
                {
                    File.WriteAllText(this.decryptedMessagePath, Encoding.UTF8.GetString(this.decryptedData));
                }
                catch (ArgumentNullException) { this.tbEncryptMessage.Text = EXCEPTION_MESSAGE_ARGUMENT_NULL; }
                catch (PathTooLongException) { this.tbEncryptMessage.Text = EXCEPTION_MESSAGE_PATH_TOO_LONG; }
                catch (DirectoryNotFoundException) { this.tbEncryptMessage.Text = EXCEPTION_MESSAGE_DIRECTORY_NOT_FOUND; }
                catch (UnauthorizedAccessException) { this.tbEncryptMessage.Text = EXCEPTION_MESSAGE_UNAUTORIZED_ACCESS; }
                catch (NotSupportedException) { this.tbEncryptMessage.Text = EXCETPION_MESSAGE_NOT_SUPPORTED; }
                catch (SecurityException) { this.tbEncryptMessage.Text = EXCEPTION_MESSAGE_SECURITY; }
            }
            catch (CryptographicException) {this.tbDecryptMessage.Text = "Odszyfrowanie wiadmości nie powidoło się. Upewnij się że zostały wygenerowane klucze lub został zaimportowany prywatny klucz.";
            }
            catch (ArgumentNullException) { this.tbDecryptMessage.Text = "Musisz wybrać plik do odszyfrowania."; }
        }
        #endregion
        #region buttonExportPublicKey_Click
        /// <summary>
        /// Akcja po wciśnięciu przycisku "Eksport klucza publicznego".
        /// Zapisuje klucze lub klucz publiczny w zależności od zaznaczonych pól w aplikacji.
        /// Zapisuje je w katalogu w którym znajduję się aplikacja. 
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void buttonExportPublicKey_Click(object sender, RoutedEventArgs e)
        {
            try
            {   
                //Zapisywanie tylko publicznego klucza do pliku - jeżeli false.
                //Jeżeli true - to wysyła publiczny i prywatny.
                File.WriteAllText(this.keysPath, this.RSAencrypt.ToXmlString(this.cbPublicAndPrivateKeyExport.IsChecked == true ? true : false), new UTF8Encoding());
                this.tbExportPrivateKey.Text = "Klucz został zapisany w " + this.keysPath + ".";
            }
            catch (ArgumentNullException) { this.tbEncryptMessage.Text = EXCEPTION_MESSAGE_ARGUMENT_NULL; }
            catch (PathTooLongException) { this.tbEncryptMessage.Text = EXCEPTION_MESSAGE_PATH_TOO_LONG; }
            catch (DirectoryNotFoundException) { this.tbEncryptMessage.Text = EXCEPTION_MESSAGE_DIRECTORY_NOT_FOUND; }
            catch (UnauthorizedAccessException) { this.tbEncryptMessage.Text = EXCEPTION_MESSAGE_UNAUTORIZED_ACCESS; }
            catch (NotSupportedException) { this.tbEncryptMessage.Text = EXCETPION_MESSAGE_NOT_SUPPORTED; }
            catch (SecurityException) { this.tbEncryptMessage.Text = EXCEPTION_MESSAGE_SECURITY; }
        }
        #endregion
        #region buttonImportKey_Click
        /// <summary>
        /// Akcja po wciśnięciu przycisku "Import zapisanego klucza".
        /// Importuje klucz lub klucze z pliku w którym znajduję się zapisane wcześniej klucze.
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void buttonImportKey_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                this.importedKey = File.ReadAllText(keysPath);
                this.tbImportKey.Text = "Klucz został zaimportowany.";
                this.isKeyImported = true;
            }
            catch (ArgumentNullException) { this.tbChosenMessage.Text = EXCEPTION_MESSAGE_ARGUMENT_NULL; }
            catch (PathTooLongException) { this.tbChosenMessage.Text = EXCEPTION_MESSAGE_PATH_TOO_LONG; }
            catch (DirectoryNotFoundException) { this.tbChosenMessage.Text = EXCEPTION_MESSAGE_DIRECTORY_NOT_FOUND; }
            catch (UnauthorizedAccessException) { this.tbChosenMessage.Text = EXCEPTION_MESSAGE_UNAUTORIZED_ACCESS; }
            catch (FileNotFoundException) { this.tbChosenMessage.Text = EXCEPTION_MESSAGE_FILE_NOT_FOUND; }
            catch (NotSupportedException) { this.tbChosenMessage.Text = EXCETPION_MESSAGE_NOT_SUPPORTED; }
            catch (IOException) { this.tbChosenMessage.Text = EXCEPTION_MESSAGE_IO; }
            catch (SecurityException) { this.tbChosenMessage.Text = EXCEPTION_MESSAGE_SECURITY; }
            catch (ArgumentException) { this.tbChosenMessage.Text = EXCEPTION_MESSAGE_ARGUMENT; }
        }
        #endregion  
    }
}

