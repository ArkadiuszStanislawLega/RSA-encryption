   M S B A M L   `   `   `  ����>  :RSA, Version=1.0.0.0, Culture=neutral, PublicKeyToken=nullclr-namespace:RSARSA  5   	       RSA.MainWindow   5   	   R NWindowsBase, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35W SPresentationCore, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35\ XPresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35D 9http://schemas.microsoft.com/winfx/2006/xaml/presentation    5   	   R NSystem.Xaml, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089:x,http://schemas.microsoft.com/winfx/2006/xaml     5   	   @d2http://schemas.microsoft.com/expression/blend/2008     5   	   Jmc;http://schemas.openxmlformats.org/markup-compatibility/2006     5   	   Z VFontAwesome.WPF, Version=4.7.0.37774, Culture=neutral, PublicKeyToken=0758b07a11a4f466-fa$http://schemas.fontawesome.io/icons/  5   	   localclr-namespace:RSA  5   	     � AllowsTransparency  .  � WindowStartupLocation$ CenterScreen=�5	   	   
������  � WindowStyle$
 None=�5   	    � Title$ 
MainWindow��5   	   $	��450��6   $
��1000��6)   .��5      �� .+�5   
   � -   5        $��
TitlePanel��5      $
��auto��5      $��30��6   .+�5      ��  �� CornerRadius$ 	10 10 0 0��6      TopGrayBrash#��[  5       J� Opacity$	 0.7Q�5      $��0 0 0 1q�5      � 5       � ColumnDefinitions 5      �� 5      $
��auto �6'   �� 5      $
��auto �6'   �� 5      $��* �6'   .+�5      �� $��Szyfrowanie RSA��6   $��20(�63    �� Padding$ 3q�5        �� TextAlignment$ Center=�5!      $��Center=�5"        	GrayBrash#��[ 5#      $
��Bold"�5$      $��40��5%      $��5q�5&      �� 5'      -   5        $��TitlePanelButtons��5(      $��Right=�5)      	 �� Orientation$	 
Horizontal=�5*      $��2��5+      $��0 0 25 0q�5,      .+�5.      �� -   5        $��Minimize��5.        FAMinimizeButton#��[ 5/      50      �� 51      -   5        $
��Exit��51        FAExitButton#��[ 52      53      55      56      57      � 5:   
   .+�5;      �� $��0q�6     MainBarBrash#��[ 6    $ 	0 0 60 60��6K   � 5<       5>      �� 5?      $
��Auto �6'   �� 5@      $
��Auto �6'   �� 5A      $��* �6'   .+�5E      � $��1��6   $��Center=�6'   $	��270��6B   $	��300��6N   
 � RowDefinitions
 5F      �� 5G      $
��auto �6(   �� 5H      $
��auto �6(   �� 5J      $��* �6(   .+�5L      �� $��0��6!   .+�5M      �� $��Klucze��6$   $ Center=�5N   $     EnabledBrash#��[ 5O   $   � 5R      .+�5S      �� -   5        $ ��cbImoprtedOrCurrentKeyShow��5S   '   {�5V   '   �� *KeyWasImported+.��5X   "   �� $!��Pokaż klucz zaimportowany.��6,   $
��Wrap=�5Y   ,   5[      "  FontAwesome.WPF.ImageAwesome  5\         Icon$ 
InfoCircle=�6.   $��16��5]   .   $��Center=�5^   .   $��Right=�5_   .   $��0 0 15 0q�5`   .     
FontsBrash   
Foreground# [ 5a   .    � ToolTip$E ?Warunkiem zaznaczenia tej kontrolki jest zaimportowanie klucza.��5b   .   5c      �� 5e      -   5        $&�� cbPublicAndPrivateCurrentKeyShow��5e   #   #��[ 5f   #   $W QJeżeli ten punkt nie jest zaznaczony to jest wyświetlany tylko publiczny klucz.��5i   #   .��5k      �� $(��"Pokaż klucz prywatny i publiczny.��6(   $
��Wrap=�5l   ,   5m      �� 5o      5p      � 5r      $��1��6   
 5s      �� 5t      $
��auto �6,   �� 5u      $
��auto �6,   .+�5w      �� $��Eksport kluczy��6$   $ Center=�5x   $   #��[ 5y   $   $��0��5z   $   �� 5|      -   5        $!��cbPublicAndPrivateKeyExport��5|   #   #��[ 6F   {�.  $��1��5~   #   .��5      �� $D��>Mają być eksportowane do pliku klucze, prywatny i publiczny.��6(   $
��Wrap=�5�   ,   $X RJeżeli nie zostanie zazaczone to pole to zostanie wysłany tylko klucz publiczny.��5�   ,   5�        5�      $ 
InfoCircle=�6*   $��1��5�   .   $��16��5�   .   $��Center=�5�   .   $��Right=�5�   .   $��0 0 15 0q�5�   .   # [ 5�   .   $S MWarunkiem zaznaczenia tej kontrolki jest wygenerowanie kluczy asymetrycznych.��5�   .   5�      �� 5�      -   5        $��40��5�      $��40��5�      $��2��6)   $��Bottom=�5�      .��5�        $ AddressCard=�6*   $��Bottom=�5�   *   $��Center=�5�   *   # [ 5�   *   5�      5�      �� 5�      $��3q�6   $��0��6/   #��[ 5�      $��60 10 10 10q�6B   $ 5 5 5 5��5�      ._�5�      �� $	 Vertical=�5�   !   $��Right=�5�   !   $	��400��5�   !     BackgroundOfPagesBrash#��[ 5�   !   .+�5�      �� $
��Auto=�6'   $
��Auto=�5�   '   $��40��5�   '   $	��400��5�   '   .��5�      �� -	   5        $��tbCreateAsmKey��5�   (   $
 Left=�5�   $   $��Center=�5�   $   $
��Wrap=�5�   $   $��10q�5�   $   $��40��5�   $   5�      �� 5�      �� 5�      $
��Auto=�6'   $
��Auto=�5�   '   $��50��5�   '   .��5�      �� -
   5        $��tbChosenMessage��5�   (   $
 Left=�5�   $   $��50��5�   $   $
��Wrap=�5�   $   $��Center=�5�   $   $��0 0 0 2q�5�   $   ��. 5�   $   5�      �� 5�      �� 5�      -   5        $��tbEncryptMessage��5�   $   $ Center=�5�   $   $��Center=�5�   $   $
��Wrap=�5�   %   $��10q�5�   $   �� 5�      �� 5�      $
��Auto=�6'   $
��Auto=�5�   '   $��50��5�   '   .��5�      �� -   5        $��tbEncryptedChosenMessage��5�   (   $
 Left=�5�   $   $��Center=�5�   $   $��50��5�   $   $��0 0 50 2q�5�   $   5�      �� 5�      �� 5�      $
��Auto=�6'   $
��Auto=�5�   '   $��50��5�   '   .��5�      �� -   5        $��tbDecryptMessage��5�   (   $
 Left=�5�   )   $��Center=�5�   )   $��0 0 50 2q�5�   )   $��30��5�   )   5�      �� 5�      �� 5�      -   5        $��tbExportPrivateKey��5�   $   $ Center=�5�   $   $��Center=�5�   $   �� 5�      �� 5�      -   5        $��tbImportKey��5�   $   $ Center=�5�   $   $��Center=�5�   $   �� 5�      5�      5�      �� 5�      $��3q�6   $��2��6/   #��[ 6?   #��[ 5�      $��
5 10 35 10q�6F   $ 10 10 10 10��5�      ._�5�      �� $	 Vertical=�6!   .+�5�      �� -   5        $��buttonCreateAsmKey��5�   !   $%��Tworzenie kluczy asymetrycznych��5�   !   5�   !   �� 5�      -   5        $��ChoseFileToEncrpyt��5�   !   $#��Wybierz plik do zaszyfrowania��5�   !   5�   !   �� 5�      -   5        $��buttonEncryptFile��5�   !   $��	Zaszyfruj��5�   !   {�.  5�   !   �� 5�      -   5        $��buttonChoseFileToDecrpyt��5�   !   $#��Wybierz plik do odszyfrowania��5�   !   5�   !   �� 5�      -   5        $��buttonDecryptFile��5�   !   $��	Odszyfruj��5�   !   {�.  5�   !   �� 5      -   5        $��buttonExportPublickKey��5  !   $ ��Eksport klucza publicznego��5   !   {�5  !   ��  �� ElementName$! cbPublicAndPrivateKeyExport�� �� Path$ 	IsEnabled��� 5     -   5        $��buttonImportPublicKey��5  !   $��Import zapisanego klucza��5  !   5  !   5
     5     5     5     5     5     