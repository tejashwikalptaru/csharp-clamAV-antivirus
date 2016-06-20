using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

//Firewall API
using NATUPNPLib;
using NETCONLib;
using NetFwTypeLib;
using System.Collections;
using System.Runtime.InteropServices;

namespace AntiVirus_Project
{
    class Firewall
    {
        private const string CLSID_FIREWALL_MANAGER = "{304CE942-6E39-40D8-943A-B913C40C9CD4}";
        private INetFwMgr manager = null;
        public bool firewallOn = false;

        private static NetFwTypeLib.INetFwMgr GetFirewallManager()
        {
            Type objectType = Type.GetTypeFromCLSID(new Guid(CLSID_FIREWALL_MANAGER));
            return Activator.CreateInstance(objectType) as NetFwTypeLib.INetFwMgr;
        }

        public bool IsFirewallInstalled
        {
            get
            {
                if (manager != null &&
                      manager.LocalPolicy != null &&
                      manager.LocalPolicy.CurrentProfile != null)
                    return true;
                else
                    return false;
            }
        }

        public Firewall()
        {
            manager = GetFirewallManager();
            if (manager != null)
                firewallOn = manager.LocalPolicy.CurrentProfile.FirewallEnabled;
            else
                firewallOn = false;
        }

        public bool FirewallStatus()
        {
            return manager.LocalPolicy.CurrentProfile.FirewallEnabled && IsFirewallInstalled;
        }

        public void FirewallStart(bool flag)
        {
            if (IsFirewallInstalled)
            {
                if (flag)
                    manager.LocalPolicy.CurrentProfile.FirewallEnabled = true;
                else
                {
                    // there will be an exception if we try to turnoff windows firewall directly via API
                    ConsoleSetups con = new ConsoleSetups();
                    con.RunExternalExe("netsh.exe", "Firewall set opmode disable");
                }
            }
        }

        public bool HasAuthorization(string applicationFullPath)
        {
            foreach (string appName in GetAuthorizedAppPaths())
            {
                // Paths on windows file systems are not case sensitive.
                if (appName.ToLower() == applicationFullPath.ToLower())
                    return true;
            }

            // Failed to locate the given app.
            return false;
        }

        public ICollection GetAuthorizedAppPaths()
        {
            if (IsFirewallInstalled && manager!=null)
            {
                ArrayList list = new ArrayList();
                //  Collect the paths of all authorized applications
                foreach (INetFwAuthorizedApplication app in manager.LocalPolicy.CurrentProfile.AuthorizedApplications)
                    list.Add(app.ProcessImageFileName);

                return list;
            }
            else return null;
        }

        public void GrantAuthorization(string applicationFullPath, string appName)
        {
            if(!HasAuthorization(applicationFullPath))
            {
                Type authAppType = Type.GetTypeFromProgID("HNetCfg.FwAuthorizedApplication", false);
                INetFwAuthorizedApplication appInfo = null;
                if (authAppType != null)
                {
                    try
                    {
                        appInfo = (INetFwAuthorizedApplication)Activator.CreateInstance(authAppType);
                    }
                    // In all other circumstances, appInfo is null.
                    catch { appInfo = null; }
                }
                if(appInfo!=null)
                {
                    appInfo.Name = appName;
                    appInfo.ProcessImageFileName = applicationFullPath;
                    manager.LocalPolicy.CurrentProfile.AuthorizedApplications.Add(appInfo);
                }
            }
        }

        public void RemoveAuthorization(string applicationFullPath)
        {
            if (HasAuthorization(applicationFullPath))
            {
                // Remove Authorization for this application
                manager.LocalPolicy.CurrentProfile.AuthorizedApplications.Remove(applicationFullPath);
            }
        }
    }
}
