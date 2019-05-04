﻿#pragma checksum "..\..\MainWindow.xaml" "{ff1816ec-aa5e-4d10-87f7-6f4963833460}" "2CC5C9F62903F17D077649D6B3F10123AEC74F2E"
//------------------------------------------------------------------------------
// <auto-generated>
//     Ten kod został wygenerowany przez narzędzie.
//     Wersja wykonawcza:4.0.30319.42000
//
//     Zmiany w tym pliku mogą spowodować nieprawidłowe zachowanie i zostaną utracone, jeśli
//     kod zostanie ponownie wygenerowany.
// </auto-generated>
//------------------------------------------------------------------------------

using RSA;
using System;
using System.Diagnostics;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Ink;
using System.Windows.Input;
using System.Windows.Markup;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Media.Effects;
using System.Windows.Media.Imaging;
using System.Windows.Media.Media3D;
using System.Windows.Media.TextFormatting;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.Windows.Shell;


namespace RSA {
    
    
    /// <summary>
    /// MainWindow
    /// </summary>
    public partial class MainWindow : System.Windows.Window, System.Windows.Markup.IComponentConnector {
        
        
        #line 15 "..\..\MainWindow.xaml"
        [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Performance", "CA1823:AvoidUnusedPrivateFields")]
        internal System.Windows.Controls.Grid TitlePanel;
        
        #line default
        #line hidden
        
        
        #line 39 "..\..\MainWindow.xaml"
        [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Performance", "CA1823:AvoidUnusedPrivateFields")]
        internal System.Windows.Controls.StackPanel TitlePanelButtons;
        
        #line default
        #line hidden
        
        
        #line 45 "..\..\MainWindow.xaml"
        [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Performance", "CA1823:AvoidUnusedPrivateFields")]
        internal System.Windows.Controls.Button Minimize;
        
        #line default
        #line hidden
        
        
        #line 48 "..\..\MainWindow.xaml"
        [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Performance", "CA1823:AvoidUnusedPrivateFields")]
        internal System.Windows.Controls.Button Exit;
        
        #line default
        #line hidden
        
        
        #line 72 "..\..\MainWindow.xaml"
        [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Performance", "CA1823:AvoidUnusedPrivateFields")]
        internal System.Windows.Controls.CheckBox cbPublicAndPrivateKeyExport;
        
        #line default
        #line hidden
        
        
        #line 91 "..\..\MainWindow.xaml"
        [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Performance", "CA1823:AvoidUnusedPrivateFields")]
        internal System.Windows.Controls.TextBlock tbCreateAsmKey;
        
        #line default
        #line hidden
        
        
        #line 103 "..\..\MainWindow.xaml"
        [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Performance", "CA1823:AvoidUnusedPrivateFields")]
        internal System.Windows.Controls.TextBlock tbChosenMessage;
        
        #line default
        #line hidden
        
        
        #line 112 "..\..\MainWindow.xaml"
        [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Performance", "CA1823:AvoidUnusedPrivateFields")]
        internal System.Windows.Controls.TextBlock tbEncryptMessage;
        
        #line default
        #line hidden
        
        
        #line 121 "..\..\MainWindow.xaml"
        [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Performance", "CA1823:AvoidUnusedPrivateFields")]
        internal System.Windows.Controls.TextBlock tbEncryptedChosenMessage;
        
        #line default
        #line hidden
        
        
        #line 131 "..\..\MainWindow.xaml"
        [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Performance", "CA1823:AvoidUnusedPrivateFields")]
        internal System.Windows.Controls.TextBlock tbDecryptMessage;
        
        #line default
        #line hidden
        
        
        #line 138 "..\..\MainWindow.xaml"
        [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Performance", "CA1823:AvoidUnusedPrivateFields")]
        internal System.Windows.Controls.TextBlock tbExportPrivateKey;
        
        #line default
        #line hidden
        
        
        #line 142 "..\..\MainWindow.xaml"
        [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Performance", "CA1823:AvoidUnusedPrivateFields")]
        internal System.Windows.Controls.TextBlock tbImportKey;
        
        #line default
        #line hidden
        
        
        #line 155 "..\..\MainWindow.xaml"
        [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Performance", "CA1823:AvoidUnusedPrivateFields")]
        internal System.Windows.Controls.Button buttonCreateAsmKey;
        
        #line default
        #line hidden
        
        
        #line 160 "..\..\MainWindow.xaml"
        [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Performance", "CA1823:AvoidUnusedPrivateFields")]
        internal System.Windows.Controls.Button ChoseFileToEncrpyt;
        
        #line default
        #line hidden
        
        
        #line 165 "..\..\MainWindow.xaml"
        [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Performance", "CA1823:AvoidUnusedPrivateFields")]
        internal System.Windows.Controls.Button buttonEncryptFile;
        
        #line default
        #line hidden
        
        
        #line 170 "..\..\MainWindow.xaml"
        [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Performance", "CA1823:AvoidUnusedPrivateFields")]
        internal System.Windows.Controls.Button buttonChoseFileToDecrpyt;
        
        #line default
        #line hidden
        
        
        #line 175 "..\..\MainWindow.xaml"
        [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Performance", "CA1823:AvoidUnusedPrivateFields")]
        internal System.Windows.Controls.Button buttonDecryptFile;
        
        #line default
        #line hidden
        
        
        #line 180 "..\..\MainWindow.xaml"
        [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Performance", "CA1823:AvoidUnusedPrivateFields")]
        internal System.Windows.Controls.Button buttonExportPublickKey;
        
        #line default
        #line hidden
        
        
        #line 185 "..\..\MainWindow.xaml"
        [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Performance", "CA1823:AvoidUnusedPrivateFields")]
        internal System.Windows.Controls.Button buttonImportPublicKey;
        
        #line default
        #line hidden
        
        private bool _contentLoaded;
        
        /// <summary>
        /// InitializeComponent
        /// </summary>
        [System.Diagnostics.DebuggerNonUserCodeAttribute()]
        [System.CodeDom.Compiler.GeneratedCodeAttribute("PresentationBuildTasks", "4.0.0.0")]
        public void InitializeComponent() {
            if (_contentLoaded) {
                return;
            }
            _contentLoaded = true;
            System.Uri resourceLocater = new System.Uri("/RSA;component/mainwindow.xaml", System.UriKind.Relative);
            
            #line 1 "..\..\MainWindow.xaml"
            System.Windows.Application.LoadComponent(this, resourceLocater);
            
            #line default
            #line hidden
        }
        
        [System.Diagnostics.DebuggerNonUserCodeAttribute()]
        [System.CodeDom.Compiler.GeneratedCodeAttribute("PresentationBuildTasks", "4.0.0.0")]
        [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Never)]
        [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Design", "CA1033:InterfaceMethodsShouldBeCallableByChildTypes")]
        [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Maintainability", "CA1502:AvoidExcessiveComplexity")]
        [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Performance", "CA1800:DoNotCastUnnecessarily")]
        void System.Windows.Markup.IComponentConnector.Connect(int connectionId, object target) {
            switch (connectionId)
            {
            case 1:
            this.TitlePanel = ((System.Windows.Controls.Grid)(target));
            
            #line 17 "..\..\MainWindow.xaml"
            this.TitlePanel.MouseLeftButtonDown += new System.Windows.Input.MouseButtonEventHandler(this.TopBarContent_MouseDown);
            
            #line default
            #line hidden
            return;
            case 2:
            this.TitlePanelButtons = ((System.Windows.Controls.StackPanel)(target));
            return;
            case 3:
            this.Minimize = ((System.Windows.Controls.Button)(target));
            
            #line 47 "..\..\MainWindow.xaml"
            this.Minimize.Click += new System.Windows.RoutedEventHandler(this.Minimize_Click);
            
            #line default
            #line hidden
            return;
            case 4:
            this.Exit = ((System.Windows.Controls.Button)(target));
            
            #line 50 "..\..\MainWindow.xaml"
            this.Exit.Click += new System.Windows.RoutedEventHandler(this.Exit_Click);
            
            #line default
            #line hidden
            return;
            case 5:
            this.cbPublicAndPrivateKeyExport = ((System.Windows.Controls.CheckBox)(target));
            return;
            case 6:
            this.tbCreateAsmKey = ((System.Windows.Controls.TextBlock)(target));
            return;
            case 7:
            this.tbChosenMessage = ((System.Windows.Controls.TextBlock)(target));
            return;
            case 8:
            this.tbEncryptMessage = ((System.Windows.Controls.TextBlock)(target));
            return;
            case 9:
            this.tbEncryptedChosenMessage = ((System.Windows.Controls.TextBlock)(target));
            return;
            case 10:
            this.tbDecryptMessage = ((System.Windows.Controls.TextBlock)(target));
            return;
            case 11:
            this.tbExportPrivateKey = ((System.Windows.Controls.TextBlock)(target));
            return;
            case 12:
            this.tbImportKey = ((System.Windows.Controls.TextBlock)(target));
            return;
            case 13:
            this.buttonCreateAsmKey = ((System.Windows.Controls.Button)(target));
            
            #line 156 "..\..\MainWindow.xaml"
            this.buttonCreateAsmKey.Click += new System.Windows.RoutedEventHandler(this.buttonCreateAsmKeys_Click);
            
            #line default
            #line hidden
            return;
            case 14:
            this.ChoseFileToEncrpyt = ((System.Windows.Controls.Button)(target));
            
            #line 161 "..\..\MainWindow.xaml"
            this.ChoseFileToEncrpyt.Click += new System.Windows.RoutedEventHandler(this.buttonChoseFileToEncrypt_Click);
            
            #line default
            #line hidden
            return;
            case 15:
            this.buttonEncryptFile = ((System.Windows.Controls.Button)(target));
            
            #line 166 "..\..\MainWindow.xaml"
            this.buttonEncryptFile.Click += new System.Windows.RoutedEventHandler(this.buttonEncryptFile_Click);
            
            #line default
            #line hidden
            return;
            case 16:
            this.buttonChoseFileToDecrpyt = ((System.Windows.Controls.Button)(target));
            
            #line 171 "..\..\MainWindow.xaml"
            this.buttonChoseFileToDecrpyt.Click += new System.Windows.RoutedEventHandler(this.buttonChoseDecryptFile_Click);
            
            #line default
            #line hidden
            return;
            case 17:
            this.buttonDecryptFile = ((System.Windows.Controls.Button)(target));
            
            #line 176 "..\..\MainWindow.xaml"
            this.buttonDecryptFile.Click += new System.Windows.RoutedEventHandler(this.buttonDecryptFile_Click);
            
            #line default
            #line hidden
            return;
            case 18:
            this.buttonExportPublickKey = ((System.Windows.Controls.Button)(target));
            
            #line 181 "..\..\MainWindow.xaml"
            this.buttonExportPublickKey.Click += new System.Windows.RoutedEventHandler(this.buttonExportPublicKey_Click);
            
            #line default
            #line hidden
            return;
            case 19:
            this.buttonImportPublicKey = ((System.Windows.Controls.Button)(target));
            
            #line 186 "..\..\MainWindow.xaml"
            this.buttonImportPublicKey.Click += new System.Windows.RoutedEventHandler(this.buttonImportKey_Click);
            
            #line default
            #line hidden
            return;
            }
            this._contentLoaded = true;
        }
    }
}

