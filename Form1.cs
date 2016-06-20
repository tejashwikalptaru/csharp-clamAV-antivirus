using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using MetroFramework;
using MetroFramework.Forms;
using nClam;
using System.IO;
using System.Diagnostics;
using System.ServiceProcess;
using System.Threading;
using System.Collections;
using System.Media;
using TejashPlayer;
using System.Security.AccessControl;
using System.Security.Principal;
using BrightIdeasSoftware;
using System.Runtime.InteropServices;
using Microsoft.Win32;
using System.Management;


namespace AntiVirus_Project
{
    public partial class Form1 : MetroForm
    {
#pragma warning disable 0618 // removes the obsolete warning
        [DllImport("process-killer.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int KillProcess(IntPtr handle, string proc_name);


        private string my_location = string.Empty;
        private Thread search = null;
        private string loc_to_search = string.Empty;
        private bool scanning = false;
        private bool suspended = false;
        private string wildcard = "*.*";
        private string smart_ext = "*.exe|*.cpl|*.reg|*.ini|*.bat|*.com|*.dll|*.pif|*.lnk|*.scr|*.vbs|*.ocx|*.drv|*.sys";
        private string[] files = null;
        private ArrayList watchers = new ArrayList();
        private DateTime sch_time;
        private string sch_loc = string.Empty;
        private bool av_service_error = false;

        private ConsoleSetups con = new ConsoleSetups();
        private ServiceController service = new ServiceController();
        private UsbManager usb = new UsbManager();
        private History his = new History();
        private Quarantine quaran = new Quarantine();
        private Exclusion exclusion = new Exclusion();
        private Firewall fw = new Firewall();
        private FolderLocker locker = new FolderLocker();
        


        //main form ctor()
        public Form1()
        {
            CheckForIllegalCrossThreadCalls = false;
            InitializeComponent();
            my_location = Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location);
        }

        //setup the scanner engine
        private void SetupScannerEngine()
        {
            //setup the scanner engine path
            string temp = my_location + "\\engine\\";

            //write the correct engine configurations according to path
            StreamWriter writter = new StreamWriter(temp + "clamd.conf");
            writter.WriteLine("TCPSocket 3310");
            writter.WriteLine("MaxThreads 2");
            writter.WriteLine("LogFile " + temp + "clamd.log");
            writter.WriteLine("DatabaseDirectory " + temp + "db");
            writter.Close();

            //insert the correct registry settings according to path
            //I am not using try catch block because, I am already running as admin
            //so probably it will not give error, will fix this if gives error in future 
            RegistryKey key;
            key = Microsoft.Win32.Registry.LocalMachine.CreateSubKey("Software\\ClamAV\\");
            key.SetValue("ConfigDir", temp);
            key.Close();
            key = Microsoft.Win32.Registry.LocalMachine.CreateSubKey("Software\\ClamAV\\");
            key.SetValue("DataDir", temp + "db");
            key.Close();


            //Install the AV scanner service
            con.RunExternalExe(temp + "clamd.exe", "--install");

            //install the AV updater service
            con.RunExternalExe(temp + "freshclam.exe", "--install");

            //start the antivirus services...
            try
            {
                string status = string.Empty;
                service.ServiceName = "FreshClam";
                status = service.Status.ToString();
                if (status == "Stopped")
                    service.Start();

                status = string.Empty;
                service.ServiceName = "ClamD";
                status = service.Status.ToString();
                if (status == "Stopped")
                    service.Start();
            }
            catch
            {
                pictureBox1.Image = Properties.Resources.unsecured;
                pictureBox3.Image = Properties.Resources.cross;
                av_service_error = true;
                MetroFramework.MetroMessageBox.Show(this, "Unable to start antivirus services, kindly restart the application or see help manual on how to start services manually", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        //stops the scanner services
        private void StopScannerEngine()
        {
            try
            {
                string status = string.Empty;
                service.ServiceName = "FreshClam";
                service.Stop();

                status = string.Empty;
                service.ServiceName = "ClamD";
                service.Stop();
            }
            catch { }
        }

        //override close
        protected override void WndProc(ref Message m)
        {
            DialogResult dr;
            if (m.Msg == 0x0010)
            {
                dr = MetroFramework.MetroMessageBox.Show(this,"You are closing the Netsky Antivirus, your PC will be unsecured then. Do you want to close?", "Confirm", MessageBoxButtons.YesNo, MessageBoxIcon.Question);
                if (dr == DialogResult.No)
                    return;
                notifyIcon1.Dispose();
                Properties.Settings.Default.usb_auto = listenUSB.Checked;
                Properties.Settings.Default.real_scan = realToggle.Checked;
                Properties.Settings.Default.smart = smart_Toggle.Checked;
                Properties.Settings.Default.history = historyToggle.Checked;
                Properties.Settings.Default.Save();
                StopScannerEngine();
                if(scanning)
                {
                    try
                    {
                        search.Abort();
                    }
                    catch { }
                }
            }
            base.WndProc(ref m);
        }

        //form load
        private void Form1_Load(object sender, EventArgs e)
        {
            metroTabControl1.SelectedIndex = 0;
            metroTabControl2.SelectedIndex = 0;
            metroProgressBar1.Maximum = 100;
            metroProgressBar1.Minimum = 0;
            metroProgressBar1.Value = 0;
            metroTile2.Enabled = false;
            metroTile3.Enabled = false;
            realToggle.Checked = Properties.Settings.Default.real_scan;
            listenUSB.Checked = Properties.Settings.Default.usb_auto;
            smart_Toggle.Checked = Properties.Settings.Default.smart;
            historyToggle.Checked = Properties.Settings.Default.history;
            metroProgressSpinner1.Visible = false;

            SetupScannerEngine(); // setup the scanner engine

            //start the usb monitor
            usb.StateChanged += new UsbStateChangedEventHandler(DoStateChanged);

            // do proper adjustment according to real time and auto usb scan settings
            realToggle_CheckedChanged(sender, e);
            listenUSB_CheckedChanged(sender, e);

            // file system watcher
            string[] drives = Directory.GetLogicalDrives();
            DriveInfo di = null;
            for(int i=0;i<drives.Length;i++)
            {
                di = new DriveInfo(drives[i]);
                if (di.IsReady)
                {
                    FileSystemWatcher watcher = new FileSystemWatcher();
                    watcher.Filter = "*.*";
                    watcher.Path = drives[i];
                    watcher.IncludeSubdirectories = true;
                    watcher.NotifyFilter = NotifyFilters.LastAccess | NotifyFilters.LastWrite| NotifyFilters.FileName | NotifyFilters.DirectoryName | NotifyFilters.Attributes;
                    watcher.Created += new FileSystemEventHandler(RealTime);
                    watcher.Renamed += new RenamedEventHandler(RealTime);
                    //watcher.Changed += new FileSystemEventHandler(RealTime);
                    watcher.InternalBufferSize = 4058;
                    watcher.EnableRaisingEvents = true;
                    watchers.Add(watcher);
                }
            }

            //firewall
            if (fw.firewallOn)
            {
                pictureBox2.Image = Properties.Resources.fine;
                metroLabel2.Text = "Firewall is ON";
                firewallToggle.Checked = true;
                foreach (string s in fw.GetAuthorizedAppPaths())
                    listBox1.Items.Add(s);
            }
            else
            {
                pictureBox2.Image = Properties.Resources.cross;
                metroLabel2.Text = "Firewall is OFF";
                firewallToggle.Checked = false;
            }

            //loads the history
            if(historyToggle.Checked)
            {
                for(int i=0;i<his.file_names.Count;i++)
                {
                    objectListView2.AddObject(new InfectionObject(his.file_names[i],his.vir_name[i]));
                }
            }

            //show the quarantine files
            foreach (string s in quaran.QuarantineItems())
                listBox2.Items.Add(s);

            //shows the exclusions
            foreach (string s in exclusion.exclusions)
                listBox3.Items.Add(s);

            //Everything is completed, now play a greet music and show balloon
            SoundPlayer snd = new SoundPlayer(Properties.Resources.ready);
            snd.Play();
            notifyIcon1.ShowBalloonTip(5, "Netsky Antivirus", "Your PC is now secured", ToolTipIcon.Info);
        }

        // start scan
        private void metroTile1_Click(object sender, EventArgs e)
        {
            if(av_service_error)
            {
                MetroFramework.MetroMessageBox.Show(this, "Antivirus services are not running, kindly restart the software or see the help manual on how to start antivirus services manually.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            if(metroRadioButton2.Checked) //quick
            {
                if(!scanning)
                {
                    loc_to_search = Path.GetPathRoot(Environment.SystemDirectory);
                    search = new Thread(new ThreadStart(ScanFolder));
                    search.Start();
                }
                return;
            }

            if (metroRadioButton3.Checked) // scan a file
            {
                openFileDialog1.Title = "Select the file please";
                openFileDialog1.Multiselect = false;
                openFileDialog1.CheckPathExists = true;
                openFileDialog1.FileName = "";
                openFileDialog1.Filter = "All files|*.*";
                openFileDialog1.SupportMultiDottedExtensions = false;

                if (DialogResult.OK == openFileDialog1.ShowDialog())
                {
                    ScanFile(openFileDialog1.FileName, false);
                }
                return;
            }
            
            if(metroRadioButton4.Checked) // custom folder
            {
                if (scanning == true)
                {
                    MetroFramework.MetroMessageBox.Show(this, "Please wait, scanning for some files is already in progress!", "Wait", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    return;
                }
                folderBrowserDialog1.Description = "Select your folder or drive";
                if (folderBrowserDialog1.ShowDialog() == DialogResult.OK)
                {
                    loc_to_search = folderBrowserDialog1.SelectedPath;
                    search = new Thread(new ThreadStart(ScanFolder));
                    search.Start();
                }
                return;
            }

            MetroFramework.MetroMessageBox.Show(this, "Please select a scan type first", "Error", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        //scan the folder or file
        private int ScanFile(string loc, bool silent)
        {
            if(av_service_error)
            {
                MetroFramework.MetroMessageBox.Show(this, "Antivirus services are not running, kindly restart the software or see the help manual to troubleshoot", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return 0;
            }

            int ret = 0;
            if (File.Exists(loc))
            {
                var clam = new ClamClient("localhost", 3310);
                var scanResult = clam.ScanFileOnServer(loc);
                switch (scanResult.Result)
                {
                    case ClamScanResults.Clean:
                        if (!silent)
                            MetroFramework.MetroMessageBox.Show(this, "The file is clean, it's not infected!", "Fine", MessageBoxButtons.OK, MessageBoxIcon.Information);
                        ret = 0;
                        break;
                    case ClamScanResults.VirusDetected:
                        {
                            if (!silent)
                            {
                                DialogResult dr = MetroFramework.MetroMessageBox.Show(this, "The file is infected\nVirus: " + scanResult.InfectedFiles.First().VirusName + "\nDo you want to delete?", "Virus Found", MessageBoxButtons.YesNo, MessageBoxIcon.Question);
                                if (dr == DialogResult.Yes)
                                    try
                                    {
                                        File.Delete(loc);
                                    }
                                    catch { }
                            }
                            ret = 1;
                        }
                        break;
                }
                return ret;
            }
            else
            {
                if(!silent)
                    MetroFramework.MetroMessageBox.Show(this, "Invalid file to scan", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                ret = 3;
                return ret;
            }
        }

        // infected file details to list
        private void AddToResult(string file, string vir_name)
        {
            string[] row1 = { vir_name };
            Invoke(new Action(() =>
            {
                ListViewItem item = objectListView1.FindItemWithText(file);
                if(item==null)
                {
                    objectListView1.AddObject(new InfectionObject(file, vir_name));
                    if (historyToggle.Checked)
                    {
                        his.AddHistory(file, vir_name); // add to history
                        objectListView2.AddObject(new InfectionObject(file, vir_name)); //adds it to history list
                    }
                }
            }));
        }

        //scan a folder
        private void ScanFolder()
        {
            if (av_service_error)
            {
                MetroFramework.MetroMessageBox.Show(this, "Antivirus services are not running, kindly restart the software or see the help manual to troubleshoot", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                try
                {
                    Invoke(new Action(() =>
                    {
                        metroProgressSpinner1.Visible = false;
                        metroProgressBar1.Value = 0;
                        metroLabel8.Text = "No scan is going on...";
                        infec.Text = "Infected Files: 0";
                        metroTile2.Enabled = false;
                        metroTile3.Enabled = false;
                        metroTile1.Enabled = true;
                        curr_File.Text = "...";
                        metroRadioButton2.Enabled = true;
                        metroRadioButton3.Enabled = true;
                        metroRadioButton4.Enabled = true;
                    }));

                    scanning = false;
                    search.Abort();
                }
                catch { }
            }

            scanning = true;
            bool error = false;
            int infected = 0;

            //if it's a quick scan, first check all the running processes
            if (metroRadioButton2.Checked)
            {
                metroLabel8.Text = "Scanning running processes";
                notifyIcon1.ShowBalloonTip(5, "Quick scan", "Scanning all running processes", ToolTipIcon.Info);
                foreach(string proc in GetAllRunningProcesses())
                {
                    if (File.Exists(proc))
                    {
                        try
                        {
                            var clam = new ClamClient("localhost", 3310);
                            var scanResult = clam.ScanFileOnServer(proc);
                            Invoke(new Action(() =>
                            {
                                curr_File.Text = proc;
                            }));

                            switch (scanResult.Result)
                            {
                                case ClamScanResults.VirusDetected:
                                    infected++;
                                    Invoke(new Action(() =>
                                    {
                                        infec.Text = "Infected Files: " + infected.ToString();
                                    }));
                                    AddToResult(proc, scanResult.InfectedFiles.First().VirusName);
                                    break;
                            }
                        }
                        catch { error = true; }
                    }
                }
                Invoke(new Action(() =>
                {
                    curr_File.Text = "...";
                }));
            }//end of process scanning

            // normal scan process follows...

            Invoke(new Action(() =>
            {
                metroTile1.Enabled = false;
                metroTile2.Enabled = true;
                metroTile3.Enabled = true;
                metroLabel8.Text = "Please wait, while we prepare a list of files to be scanned. It may take some time...";
                metroProgressSpinner1.Visible = true;
                metroProgressSpinner1.Show();

                metroRadioButton2.Enabled = false;
                metroRadioButton3.Enabled = false;
                metroRadioButton4.Enabled = false;
            }));
            
            if(smart_Toggle.Checked)
                files= getFiles(loc_to_search, smart_ext, SearchOption.AllDirectories);
            else
                files = getFiles(loc_to_search, wildcard, SearchOption.AllDirectories);
            int total = files.Length;

            Invoke(new Action(() =>
            {
                metroProgressSpinner1.Visible = false;
                metroLabel8.Text = "Scanning: " + loc_to_search + " (" + total.ToString() + " file)";
                metroProgressBar1.Maximum = total;
                metroProgressBar1.Minimum = 0;
                metroProgressBar1.Value = 0;
                notifyIcon1.ShowBalloonTip(5, "Netsky Scanning...", "Virus scan has been started", ToolTipIcon.Info);
            }));

            foreach(string file in files)
            {
                if (File.Exists(file))
                {
                    try
                    {
                        var clam = new ClamClient("localhost", 3310);
                        var scanResult = clam.ScanFileOnServer(file);
                        Invoke(new Action(() =>
                        {
                            curr_File.Text = file;
                        }));
                        
                        switch (scanResult.Result)
                        {
                            case ClamScanResults.VirusDetected:
                                infected++;
                                Invoke(new Action(() =>
                                {
                                    infec.Text = "Infected Files: " + infected.ToString();
                                }));
                                AddToResult(file, scanResult.InfectedFiles.First().VirusName);
                                break;
                        }
                    }
                    catch { error = true; }

                }
                Invoke(new Action(() =>
                {
                    metroProgressBar1.Value = (metroProgressBar1.Value + 1);
                }));
                
            }
            if (infected > 0)
            {
                // virus found
                SoundPlayer snd = new SoundPlayer(Properties.Resources.virfound);
                snd.Play();
                Invoke(new Action(() =>
                {
                    objectListView1.Visible = true;
                    objectListView1.Show();
                    //listView1.Visible = true;
                    //listView1.Show();
                    metroTabControl1.SelectedIndex = 2;
                }));
                
            }

            if(error)
            {
                /*
                Invoke(new Action(() =>
                {
                    metroTabControl1.SelectedIndex = 0;
                    pictureBox1.Image = Properties.Resources.unsecured;
                    pictureBox3.Image = Properties.Resources.cross;
                }));
                
                MetroFramework.MetroMessageBox.Show(this, "There is a problem with scanner engine, kindly restart the antivirus", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                 */
            }

            files = null; // allow garbage collector to collect it
            Invoke(new Action(() =>
            {
                metroProgressSpinner1.Visible = false;
                metroProgressBar1.Value = 0;
                metroLabel8.Text = "No scan is going on...";
                infec.Text = "Infected Files: 0";
                metroTile2.Enabled = false;
                metroTile3.Enabled = false;
                metroTile1.Enabled = true;
                curr_File.Text = "...";
                metroRadioButton2.Enabled = true;
                metroRadioButton3.Enabled = true;
                metroRadioButton4.Enabled = true;
            }));
            
            scanning = false;
            

            try
            {
                search.Abort();
            }
            catch { }
        }

        // check if a path is drive or not
        public static bool IsLogicalDrive(string path)
        {
            bool IsRoot = false;
            DirectoryInfo d = new DirectoryInfo(path);
            if (d.Parent == null) { IsRoot = true; }
            return IsRoot;
        }

        // get the files from the given path
        public string[] getFiles(string SourceFolder, string Filter, System.IO.SearchOption searchOption)
        {
            ArrayList alFiles = new ArrayList();
            string[] MultipleFilters = Filter.Split('|');

            if (IsLogicalDrive(SourceFolder))
            {
                foreach (string d in Directory.GetDirectories(SourceFolder))
                {
                    foreach (string FileFilter in MultipleFilters)
                    {
                        try
                        {
                            alFiles.AddRange(Directory.GetFiles(d, FileFilter, searchOption));
                        }
                        catch { continue; }
                    }
                }
            }
            else
            {
                foreach (string FileFilter in MultipleFilters)
                {
                    try
                    {
                        alFiles.AddRange(Directory.GetFiles(SourceFolder, FileFilter, searchOption));
                    }
                    catch { continue; }
                }
            }

            return (string[])alFiles.ToArray(typeof(string));
        }

        //delete the found virus
        private void metroTile4_Click(object sender, EventArgs e)
        {
            string path = string.Empty;
            for (int i = 0; i < objectListView1.Items.Count; i++)
            {
                path = objectListView1.Items[i].SubItems[0].Text;
                try
                {
                    KillProcess(this.Handle, path); // try to kill the process before deleting it
                    File.Delete(path);
                }
                catch { }
            }
            objectListView1.Items.Clear();
        }

        //pause the on going scanning
        private void metroTile2_Click(object sender, EventArgs e)
        {
            if (scanning)
            {
                if (suspended)
                {
                    try
                    {
                        search.Resume();
                        suspended = false;
                        metroTile2.Text = "Pause";
                    }
                    catch { }
                }
                else
                {
                    try
                    {
                        search.Suspend();
                        metroTile2.Text = "Resume";
                        suspended = true;
                    }
                    catch { }
                }
            }
        }

        //stop the on going scanning
        private void metroTile3_Click(object sender, EventArgs e)
        {
            if(scanning)
            {
                try
                {
                    files = null;
                    metroProgressSpinner1.Visible = false;
                    metroProgressBar1.Value = 0;
                    scanning = false;
                    curr_File.Text = "...";
                    metroLabel8.Text = "No scan is going on...";
                    infec.Text = "Infected Files: 0";
                    curr_File.Text = "...";
                    metroTile2.Enabled = false;
                    metroTile3.Enabled = false;
                    metroTile1.Enabled = true;
                    metroRadioButton2.Enabled = true;
                    metroRadioButton3.Enabled = true;
                    metroRadioButton4.Enabled = true;
                    search.Abort();
                }
                catch { }
            }
        }

        //show about from system tray
        private void aboutToolStripMenuItem_Click(object sender, EventArgs e)
        {
            this.Show();
            this.Visible = true;
            metroTabControl1.SelectedIndex = 4;
        }

        //exit from system tray
        private void exitToolStripMenuItem_Click(object sender, EventArgs e)
        {
            this.Close();
        }

        //show hide from system tray
        private void showHideToolStripMenuItem_Click(object sender, EventArgs e)
        {
            if (this.Visible)
                this.Hide();
            else
            {
                this.Show();
                this.Visible = true;
            }
        }

        //mouse double click on system tray icon
        private void notifyIcon1_MouseDoubleClick(object sender, MouseEventArgs e)
        {
            showHideToolStripMenuItem_Click(sender, e);
        }

        // handles the new usb disk add
        private void DoStateChanged(UsbStateChangedEventArgs e)
        {
            if (e.State == UsbStateChange.Added)
            {
               if(!scanning)
               {
                   if (listenUSB.Checked)
                   {
                       loc_to_search = e.Disk.Name;
                       search = new Thread(new ThreadStart(ScanFolder));
                       search.Start();
                       metroTabControl1.SelectedIndex = 1;
                   }
               }
            }
        }

        //real time scanning, toggle event
        private void realToggle_CheckedChanged(object sender, EventArgs e)
        {
            if (realToggle.Checked)
            {
                metroLabel14.Text = "Realtime scanning...";
                pictureBox6.Image = Properties.Resources.fine;
                pictureBox3.Image = Properties.Resources.fine;
                pictureBox1.Image = Properties.Resources.secured;
            }
            else
            {
                metroLabel14.Text = "Realtime scanning is disabled";
                pictureBox6.Image = Properties.Resources.cross;
                pictureBox3.Image = Properties.Resources.cross;
                pictureBox1.Image = Properties.Resources.unsecured;
            }

        }

        //auto usb scan toggle
        private void listenUSB_CheckedChanged(object sender, EventArgs e)
        {
            if (listenUSB.Checked)
                pictureBox7.Image = Properties.Resources.fine;
            else
                pictureBox7.Image = Properties.Resources.cross;
        }

        //update
        private void metroTile5_Click(object sender, EventArgs e)
        {

        }

        //Real time scanner 
        private void RealTime(object sender, FileSystemEventArgs e)
        {
            if (av_service_error)
                return;
            if (exclusion.isExclusion(e.FullPath))
                return;

            FileAttributes attr;
            int inf = 0;
            try
            {
                if (realToggle.Checked)
                {
                    Invoke(new Action(() =>
                    {
                        metroLabel13.Text = e.FullPath;
                    }));

                    attr = File.GetAttributes(e.FullPath);
                    if ((attr & FileAttributes.Directory) == FileAttributes.Directory)
                    {
                        //give some to create the whole dir at once...
                        Thread.Sleep(3000);
                        //Now start scanning the folder

                        string[] fls = getFiles(e.FullPath, wildcard, SearchOption.AllDirectories);
                        if(fls!=null)
                        {
                            //MessageBox.Show(fls.Length.ToString());
                            foreach(string s in fls)
                            {
                                if(File.Exists(s))
                                {
                                    var clam = new ClamClient("localhost", 3310);
                                    var scanResult = clam.ScanFileOnServer(s);
                                    switch (scanResult.Result)
                                    {
                                        case ClamScanResults.VirusDetected:
                                            {
                                                inf++;
                                                AddToResult(s, scanResult.InfectedFiles.First().VirusName);
                                                Invoke(new Action(() =>
                                                {
                                                    objectListView1.Visible = true;
                                                    objectListView1.Show();
                                                    this.Visible = true;
                                                    this.Show();
                                                    metroTabControl1.SelectedIndex = 2;
                                                }));

                                            }
                                            break;
                                    }
                                }
                            }
                            //Every found virus is listed, now play sound
                            if(inf>0)
                            {
                                SoundPlayer snd = new SoundPlayer(Properties.Resources.virfound);
                                snd.Play();
                            }
                        }
                        
                    }
                    else
                    {
                        //it's a file let's scan it...
                        var clam = new ClamClient("localhost", 3310);
                        var scanResult = clam.ScanFileOnServer(e.FullPath);
                        switch (scanResult.Result)
                        {
                            case ClamScanResults.VirusDetected:
                                {
                                    AddToResult(e.FullPath, scanResult.InfectedFiles.First().VirusName);
                                    SoundPlayer snd = new SoundPlayer(Properties.Resources.virfound);
                                    snd.Play();
                                    Invoke(new Action(() =>
                                    {
                                        objectListView1.Visible = true;
                                        objectListView1.Show();
                                        this.Visible = true;
                                        this.Show();
                                        metroTabControl1.SelectedIndex = 2;
                                    }));
                                }
                                break;
                        }
                    }
                }
            }
            catch { }
        }

        //folder permission checks
        public static bool HasFolderWritePermission(string path)
        {
            int c = 0;
            try
            {
                DirectoryInfo di = new DirectoryInfo(path);
                DirectorySecurity acl = di.GetAccessControl();
                AuthorizationRuleCollection rules = acl.GetAccessRules(true, true, typeof(NTAccount));

                WindowsIdentity currentUser = WindowsIdentity.GetCurrent();
                WindowsPrincipal principal = new WindowsPrincipal(currentUser);
                foreach (AuthorizationRule rule in rules)
                {
                    FileSystemAccessRule fsAccessRule = rule as FileSystemAccessRule;
                    if (fsAccessRule == null)
                        continue;

                    if ((fsAccessRule.FileSystemRights & FileSystemRights.WriteData) > 0)
                    {
                        NTAccount ntAccount = rule.IdentityReference as NTAccount;
                        if (ntAccount == null)
                        {
                            continue;
                        }
                        if (principal.IsInRole(ntAccount.Value))
                        {
                            c++;
                            continue;
                        }
                    }
                }
                if (c > 0) return true;
                else return false;
            }
            catch { return false; }
        }

        //quick scan from system tray
        private void scanToolStripMenuItem_Click(object sender, EventArgs e)
        {
            metroRadioButton2.Checked = true;
            metroTile1_Click(sender, e);
        }

        // main minimize button on form
        private void metroTile6_Click(object sender, EventArgs e)
        {
            if (this.Visible)
                this.Hide();
        }

        //firewall on off
        private void metroToggle1_CheckedChanged(object sender, EventArgs e)
        {
            if(firewallToggle.Checked)
            {
                fw.FirewallStart(true);
                pictureBox2.Image = Properties.Resources.fine;
                metroLabel2.Text = "Firewall is ON";
            }
            else
            {
                con.RunExternalExe("netsh.exe", "Firewall set opmode disable");
                pictureBox2.Image = Properties.Resources.cross;
                metroLabel2.Text = "Firewall is OFF";
            }
        }

        //clear the history
        private void metroTile7_Click(object sender, EventArgs e)
        {
            his.DelHistory();
            objectListView2.ClearObjects();
        }

        // move selected viruses to Quarantine
        private void metroTile8_Click(object sender, EventArgs e)
        {
            if(objectListView1.Items.Count>0)
            {
                int count = objectListView1.CheckedObjects.Count;
                if (count > 0)
                {
                    for (int i = 0; i < objectListView1.Items.Count; i++)
                    {
                        if (objectListView1.Items[i].Checked)
                        {
                            string path = quaran.AddQuarantine(objectListView1.Items[i].SubItems[0].Text);
                            listBox2.Items.Add(path);
                            try
                            {
                                File.Delete(objectListView1.Items[i].SubItems[0].Text);
                            }
                            catch { }
                        }
                    }
                    MetroFramework.MetroMessageBox.Show(this, "Selected item has been successfully moved to quarantine", "Done", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    objectListView1.UncheckAll();
                }
                else
                    MetroFramework.MetroMessageBox.Show(this, "No item selected. Please select any item to move into quarantine", "Error", MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
            }
        }

        //restore selected quarantine item
        private void restoreThisItemToolStripMenuItem_Click(object sender, EventArgs e)
        {
            if(listBox2.Items.Count>0)
            {
                if (listBox2.SelectedItems.Count > 0)
                {
                    string path = listBox2.Items[listBox2.SelectedIndex].ToString();
                    if (File.Exists(path))
                    {
                        DialogResult dr = MetroFramework.MetroMessageBox.Show(this, "Do you want to restore the selcted item? Restoring viruses may infect your system, do you still want to restore it?", "Confirm", MessageBoxButtons.YesNo, MessageBoxIcon.Question);
                        if(dr == DialogResult.Yes)
                        {
                            folderBrowserDialog1.Description = "Select your folder or drive to save it";
                            if (folderBrowserDialog1.ShowDialog() == DialogResult.OK)
                            {
                                quaran.RestoreQuarantine(path, folderBrowserDialog1.SelectedPath);
                                listBox2.Items.RemoveAt(listBox2.SelectedIndex);
                            }
                        }
                    }
                    else
                        MetroFramework.MetroMessageBox.Show(this, "The selected item does not exists now! It can not be restored", "Unable to restore", MessageBoxButtons.OK, MessageBoxIcon.Stop);
                }
            }
        }

        //Delete the selected quarantine file
        private void deleteThisItemToolStripMenuItem_Click(object sender, EventArgs e)
        {
            if (listBox2.Items.Count > 0)
            {
                if (listBox2.SelectedItems.Count > 0)
                {
                    string path = listBox2.Items[listBox2.SelectedIndex].ToString();
                    if (File.Exists(path))
                    {
                        try { File.Delete(path); }
                        catch { }
                        listBox2.Items.RemoveAt(listBox2.SelectedIndex);
                    }
                    else
                        MetroFramework.MetroMessageBox.Show(this, "The selected item does not exists now! It can not be restored", "Unable to restore", MessageBoxButtons.OK, MessageBoxIcon.Stop);
                }
            }
        }

        //clear all quarantine
        private void metroTile9_Click(object sender, EventArgs e)
        {
            quaran.ClearQuarantine();
            listBox2.Items.Clear();
        }

        //scheduled scanning
        private void scheduledToggle_CheckedChanged(object sender, EventArgs e)
        {
            if (scheduledToggle.Checked)
            {
                if(metroRadioButton1.Checked)
                {
                    //custom folder
                    folderBrowserDialog1.Description = "Select your folder or drive";
                    if (folderBrowserDialog1.ShowDialog() == DialogResult.OK)
                    {
                        sch_loc = folderBrowserDialog1.SelectedPath;
                        sch_time = dateTimePicker1.Value;
                        timer1.Interval = 1000;
                        timer1.Start();
                        dateTimePicker1.Enabled = false;
                        metroRadioButton1.Enabled = false;
                        metroRadioButton5.Enabled = false;
                        metroLabel22.Text = "Custom scan: " + sch_loc;
                        return;
                    }
                }
                if(metroRadioButton5.Checked)
                {
                    //quick
                    sch_loc = Path.GetPathRoot(Environment.SystemDirectory);
                    sch_time = dateTimePicker1.Value;
                    timer1.Interval = 1000;
                    timer1.Start();
                    dateTimePicker1.Enabled = false;
                    metroRadioButton1.Enabled = false;
                    metroRadioButton5.Enabled = false;
                    metroLabel22.Text = "Quick scan scheduled";
                    return;
                }
                scheduledToggle.Checked = false;
                MetroFramework.MetroMessageBox.Show(this, "Please select a scan type to schedule a scan", "Error", MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
            }
            else
            {
                dateTimePicker1.Enabled = true;
                metroRadioButton1.Enabled = true;
                metroRadioButton5.Enabled = true;
                metroLabel22.Text = "No scan scheduled";
                timer1.Stop();
            }
        }

        //scheduled scanning timer
        private void timer1_Tick(object sender, EventArgs e)
        {
            if (sch_time.Hour == DateTime.Now.Hour && sch_time.Minute == DateTime.Now.Minute && sch_time.ToString("tt") == DateTime.Now.ToString("tt"))
            {
                //time matched...
                if(!scanning)
                {
                    dateTimePicker1.Enabled = true;
                    metroRadioButton1.Enabled = true;
                    metroRadioButton5.Enabled = true;
                    metroLabel22.Text = "No scan scheduled";
                    scheduledToggle.Checked = false;
                    timer1.Stop();
                    metroTabControl1.SelectedIndex = 1;
                    loc_to_search = sch_loc;
                    search = new Thread(new ThreadStart(ScanFolder));
                    search.Start();
                    if (metroRadioButton1.Checked)
                        metroRadioButton4.Checked = true;
                    if (metroRadioButton5.Checked)
                        metroRadioButton2.Checked = true;
                }
            }
        }

        //returns all the running processes path
        private List<string> GetAllRunningProcesses()
        {
            List<string> list = new List<string>();
            var wmiQueryString = "SELECT ProcessId, ExecutablePath, CommandLine FROM Win32_Process";
            using (var searcher = new ManagementObjectSearcher(wmiQueryString))
            using (var results = searcher.Get())
            {
                var query = from p in Process.GetProcesses()
                            join mo in results.Cast<ManagementObject>()
                            on p.Id equals (int)(uint)mo["ProcessId"]
                            select new
                            {
                                Process = p,
                                Path = (string)mo["ExecutablePath"],
                                CommandLine = (string)mo["CommandLine"],
                            };
                foreach (var item in query)
                {
                    list.Add(item.Path);
                }
            }
            return list;
        }

        //add folder in exclusion
        private void metroTile11_Click(object sender, EventArgs e)
        {
            folderBrowserDialog1.Description = "Select a drive or folder";
            if(folderBrowserDialog1.ShowDialog() == DialogResult.OK)
            {
                exclusion.AddExclusion(folderBrowserDialog1.SelectedPath);
                listBox3.Items.Add(folderBrowserDialog1.SelectedPath);
            }
        }

        //add a file in exclusion
        private void metroTile10_Click(object sender, EventArgs e)
        {
            openFileDialog1.Title = "Select the file please";
            openFileDialog1.Multiselect = false;
            openFileDialog1.CheckPathExists = true;
            openFileDialog1.FileName = "";
            openFileDialog1.Filter = "All files|*.*";
            openFileDialog1.SupportMultiDottedExtensions = false;

            if (DialogResult.OK == openFileDialog1.ShowDialog())
            {
                exclusion.AddExclusion(openFileDialog1.FileName);
                listBox3.Items.Add(openFileDialog1.FileName);
            }
        }

        //clears all the exclusion
        private void metroTile12_Click(object sender, EventArgs e)
        {
            exclusion.ClearExclusion();
            listBox3.Items.Clear();
        }

        //remove a selected exclusion
        private void removeToolStripMenuItem_Click(object sender, EventArgs e)
        {
            if (listBox3.Items.Count > 0)
            {
                if (listBox3.SelectedItems.Count > 0)
                {
                    string path = listBox3.Items[listBox3.SelectedIndex].ToString();
                    exclusion.DelExclusion(path);
                    listBox3.Items.RemoveAt(listBox3.SelectedIndex);
                }
            }
        }

        //remove the vault
        private void metroTile14_Click(object sender, EventArgs e)
        {
            if (locker.no_valut)
                MetroFramework.MetroMessageBox.Show(this, "There is no vault to remove", "Error", MessageBoxButtons.OK, MessageBoxIcon.Information);
            else
            {
                DialogResult dr = MetroFramework.MetroMessageBox.Show(this, "Deleting a vault will delete all the files inside the vault. Kindly take a backup of your files first\nDo you want to delete the vault?", "Confirm", MessageBoxButtons.YesNo, MessageBoxIcon.Question);
                if (dr == DialogResult.Yes)
                    locker.DestroyFolder(this);
            }
        }

        //vault lock or create
        private void metroTile13_Click(object sender, EventArgs e)
        {
            locker.CreateOrUnlockFolder(this);
        }

        //lock the opened vault
        private void metroTile15_Click(object sender, EventArgs e)
        {
            locker.LockFolder(this);
        }


    } //end of class
} //end of namespace
