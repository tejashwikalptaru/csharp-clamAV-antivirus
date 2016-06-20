using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using MetroFramework.Forms;

namespace AntiVirus_Project
{
    public partial class VaultPassword : MetroForm
    {
        public string password { get; set; } 
        public VaultPassword()
        {
            InitializeComponent();
        }

        private void metroTile1_Click(object sender, EventArgs e)
        {
            if (metroTextBox1.Text.Trim().Length >= 2)
            {
                password = metroTextBox1.Text.Trim();
                this.Close();
            }
        }
    }
}
