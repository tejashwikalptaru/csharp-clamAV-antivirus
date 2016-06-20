using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace AntiVirus_Project
{
    class InfectionObject
    {
        public string File
        {
            get { return file; }
            set { file = value; }
        }
        private string file;

        public string Virus
        {
            get { return virus; }
            set { virus = value; }
        }
        private string virus;

        public InfectionObject(string fileName, string vir_name)
        {
            this.file = fileName;
            this.virus = vir_name;
        }
    }
}
