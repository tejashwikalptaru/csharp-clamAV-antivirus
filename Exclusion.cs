using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using TejashPlayer;
using System.IO;
using System.Text.RegularExpressions;

namespace AntiVirus_Project
{
    class Exclusion
    {
        private IniFile ini = null;
        private string loc = string.Empty;
        public List<string> exclusions = new List<string>();

        public Exclusion()
        {
            loc = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            loc = loc + "\\NetSky\\";

            if (Directory.Exists(loc))
            {
                loc = loc + "NetSky_Exclusion.db";
                if (File.Exists(loc))
                {
                    ini = new IniFile(loc);
                    string t = ini.IniReadValue("Total_Exclusion", "Value");
                    if (t.Trim().Length > 0)
                    {
                        int total = Convert.ToInt32(t);
                        for (int i = 1; i <= total; i++)
                        {
                            string h = ini.IniReadValue("Exclusion", i.ToString());
                            if (h.Trim().Length > 0)
                            {
                                if(Directory.Exists(h))
                                    exclusions.Add(h);
                                if (File.Exists(h))
                                    exclusions.Add(h);
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
                File.Create(loc + "Netsky_Exclusion.db");
                loc = loc + "Netsky_Exclusion.db";
            }
        }

        public bool isExclusion(string path)
        {
            if (exclusions != null)
            {
                foreach (string ex in exclusions)
                {
                    if (path.Contains(ex))
                        return true;
                }
                return false;
            }
            else return false;
        }

        public void AddExclusion(string path)
        {
            IniFile ins = new IniFile(loc);
            int index = 0;
            string t = string.Empty;
            try
            {
                t = ins.IniReadValue("Total_Exclusion", "Value");
            }
            catch { }
            if (t.Trim().Length > 0)
            {
                index = Convert.ToInt32(t);
                index++;
            }
            else
                index++;
            exclusions.Add(path);
            ins.IniWriteValue("Exclusion", index.ToString(), path);
            ins.IniWriteValue("Total_Exclusion", "Value", index.ToString());
        }

        public void DelExclusion(string path)
        {
            IniFile ins = new IniFile(loc);
            string t = string.Empty;
            int total = 0;
            try
            {
                t = ins.IniReadValue("Total_Exclusion", "Value");
            }
            catch { }
            if (t.Trim().Length > 0)
            {
                total = Convert.ToInt32(t);
                for(int i=1;i<=total;i++)
                {
                    t = ins.IniReadValue("Exclusion", i.ToString());
                    if(t==path)
                    {
                        ins.IniWriteValue("Exclusion", i.ToString(), path + "netsky.removed.exclusion");
                        exclusions.Remove(path);
                    }
                }
            }
        }

        public void ClearExclusion()
        {
            if (File.Exists(loc))
            {
                try
                {
                    File.Delete(loc);
                    exclusions = null;
                }
                catch { }
            }
        }
    }
}