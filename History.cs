using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using TejashPlayer;
using System.IO;
using System.Text.RegularExpressions;

namespace AntiVirus_Project
{
    class History
    {
        private IniFile ini = null;
        private string loc = string.Empty;
        public List<string> file_names = new List<string>();
        public List<string> vir_name = new List<string>();

        public History()
        {
            loc = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            loc = loc + "\\NetSky\\";

            if (Directory.Exists(loc))
            {
                loc = loc + "NetSky_History.db";
                if (File.Exists(loc))
                {
                    ini = new IniFile(loc);
                    string t = ini.IniReadValue("Total_History", "Value");
                    if (t.Trim().Length > 0)
                    {
                        int total = Convert.ToInt32(t);
                        for (int i = 1; i <= total; i++)
                        {
                            string h = ini.IniReadValue("History", i.ToString());
                            if (h.Trim().Length > 0)
                            {
                                string[] data = Regex.Split(h, "#GAP#");
                                if (data.Length == 2)
                                {
                                    file_names.Add(data[0]);
                                    vir_name.Add(data[1]);
                                }
                            }
                        }
                    }
                }
                else
                {
                    File.Create(loc);
                }
            }
            else
            {
                Directory.CreateDirectory(loc);
                File.Create(loc + "Netsky_History.db");
                loc = loc + "Netsky_History.db";
            }
        }

        public void AddHistory(string file, string vir_name)
        {
            IniFile ins = new IniFile(loc);
            int index = 0;
            string t = string.Empty;
            try
            {
                t = ins.IniReadValue("Total_History", "Value");
            }
            catch { }
            if (t.Trim().Length > 0)
            {
                index = Convert.ToInt32(t);
                index++;
            }
            else
                index++;
            string val = file + "#GAP#" + vir_name;
            file_names.Add(file);
            this.vir_name.Add(vir_name);
            ins.IniWriteValue("History", index.ToString(), val);
            ins.IniWriteValue("Total_History", "Value", index.ToString());
        }

        public void DelHistory()
        {
            if(File.Exists(loc))
            {
                try
                {
                    File.Delete(loc);
                    file_names = null;
                    vir_name = null;
                }
                catch { }
            }
        }
    }
}
