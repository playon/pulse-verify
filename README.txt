VPU network check (pulse-verify)
================================

Checks whether a network is ready for a Pixellot VPU: that the firewall
lets it stream, update and be supported. Run it before the VPU arrives.

The firewall rules it checks are in the NFHS Network article:
https://support.nfhsnetwork.com/s/article/Network-and-Firewall-Setup-NFHS

No install and no admin rights needed. It makes outbound connections only
and changes nothing on this computer. It takes about a minute.


How to run it
-------------

1. Use a Windows computer plugged into the same network segment the VPU
   will use (same VLAN, same switch port profile, same firewall policy).
   Guest Wi-Fi or a staff VLAN will give you the wrong answer.

2. Before unzipping, right-click the zip, choose Properties, tick Unblock
   and click OK. Otherwise Windows may warn about running a file from the
   internet:

     "The publisher could not be verified"   Click Run.
     "Windows protected your PC"             Click More info, then
                                             Run anyway.

3. Unzip the folder and double-click Run-PulseVerify.bat.

4. The tool first shows this computer's IP configuration. Check it matches
   the Pixellot's network (IP range, gateway, DNS) before continuing.

5. Answer the questions. Answer ? if you are not sure; the report notes it.

6. The report opens in your browser. It starts with a verdict:

     Ready                         Nothing to change.
     Ready, with items to check    Works, but look at the items listed.
     Not ready                     Something the VPU needs is blocked.

   Fix anything under "Changes needed", starting at row 1, then run it
   again.


What's in this folder
---------------------

  Run-PulseVerify.bat    Double-click to run.
  Test-PulseVerify.ps1   The checks (PowerShell). Readable in Notepad.
  endpoints.json         The domains and ports it tests.
  README.txt             This file.

Reports are saved in a "reports" folder and logs in a "logs" folder next
to these files. You can delete the whole folder when you are done.
