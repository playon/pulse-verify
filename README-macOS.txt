VPU network check (pulse-verify) for macOS
==========================================

Checks whether a network is ready for a Pixellot VPU: that the firewall
lets it stream, update and be supported. Run it before the VPU arrives.

The firewall rules it checks are in the NFHS Network article:
https://support.nfhsnetwork.com/s/article/Network-and-Firewall-Setup-NFHS

How to run it
-------------

1. Use a Mac plugged into the same network segment the VPU will use
   (same VLAN, same switch port profile, same firewall policy). Guest
   Wi-Fi or a staff VLAN will give you the wrong answer.

2. Unzip the download and double-click Run-PulseVerify.command in the
   pulse-verify-macos folder.

   The first time, macOS says it "Not Opened" because the file was
   downloaded. Click Done, open System Settings, choose Privacy &
   Security, scroll down to Security and click Open Anyway next to
   Run-PulseVerify.command. Confirm with your password, then click Open.
   (On macOS 14 and earlier: Control-click the file, choose Open, then
   click Open.)

3. A Terminal window opens. The tool first shows this computer's IP
   configuration. Check it matches the Pixellot's network (IP range,
   gateway, DNS) before continuing.

4. Answer the questions. Answer ? if you are not sure; the report notes it.
   If you say yes to reviewing the firewall article, it opens in your web
   browser.

5. The report opens in your browser. It starts with a verdict:

     Ready                         Nothing to change.
     Ready, with items to check    Works, but look at the items listed.
     Not ready                     Something the VPU needs is blocked.

   Fix anything under "Changes needed", starting at row 1, then run it
   again.

   The report also has a firewall rule sheet: every rule the VPU needs,
   with this run's result for each. It is saved next to the report as a
   .csv file, to import or forward to whoever manages the firewall.


What's in this folder
---------------------

  Run-PulseVerify.command  Double-click to run.
  Test-PulseVerify.ps1     The checks (PowerShell). Readable in TextEdit.
  endpoints.json           The domains and ports it tests.
  powershell               Microsoft PowerShell 7, used to run the checks.
                           Nothing is installed.
  README.txt               This file.

Reports are saved in a "reports" folder and logs in a "logs" folder next
to these files. You can delete the whole folder when you are done.
