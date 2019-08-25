from PyQt5 import QtWidgets,uic
from PyQt5.QtWidgets import QFileDialog
import errno, os, winreg, time, datetime, re
from tabulate import tabulate

proc_arch = os.environ['PROCESSOR_ARCHITECTURE'].lower()
proc_arch64 = os.environ['PROCESSOR_ARCHITEW6432'].lower()


def printt():
   print("button clicked")

def lapps():
 def left(s, amount):
     return s[:amount]

 def right(s, amount):
     return s[-amount:]

 def mid(s, offset, amount):
     return s[offset:offset+amount]

 proc_arch = os.environ['PROCESSOR_ARCHITECTURE'].lower()
 proc_arch64 = os.environ['PROCESSOR_ARCHITEW6432'].lower()

 if proc_arch == 'x86' and not proc_arch64:
     arch_keys = {0}
 elif proc_arch == 'x86' or proc_arch == 'amd64':
     arch_keys = {winreg.KEY_WOW64_32KEY, winreg.KEY_WOW64_64KEY}
 else:
     raise Exception("Unhandled arch: %s" % proc_arch)
 applist=[]
 for arch_key in arch_keys:
     key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", 0, winreg.KEY_READ | arch_key)
     for i in range(0, winreg.QueryInfoKey(key)[0]):
         skey_name = winreg.EnumKey(key, i)
         skey = winreg.OpenKey(key, skey_name)
         try:
             name = winreg.QueryValueEx(skey, 'DisplayName')[0]
             installdate = winreg.QueryValueEx(skey, 'InstallDate')[0]
             il=left(installdate,4)
             ir=right(installdate,2)
             im=mid(installdate,4,2)
             k="-"
             l=il+k+im+k+ir
             installlocation = winreg.QueryValueEx(skey, 'InstallLocation')[0]
             installsource = winreg.QueryValueEx(skey, 'InstallSource')[0]
             subapplist=[]
             subapplist.append(name)
             subapplist.append(l)
             subapplist.append(installlocation)
             subapplist.append(installsource)
 
             applist.append(subapplist)
            
            #print(name+"                     "+installdate+"             "+installlocation+"           "+installsource)
            #sublist =list()
            #applist.append(name)
            #print(applist)
         except OSError as e:
             if e.errno == errno.ENOENT:
                 # DisplayName doesn't exist in this skey
                 pass
         finally:
             skey.Close()

 call.tencontent.append(tabulate(applist, headers=["Application Name","Install Date", "Install Location", "Install Source"]))


def lusb():
 if proc_arch == 'x86' and not proc_arch64:
     arch_keys = {0}
 elif proc_arch == 'x86' or proc_arch == 'amd64':
     arch_keys = {winreg.KEY_WOW64_32KEY, winreg.KEY_WOW64_64KEY}
 else:
     raise Exception("Unhandled arch: %s" % proc_arch)

 for arch_key in arch_keys:
     key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Enum\USBSTOR", 0, winreg.KEY_READ | arch_key)
     for i in range(0, winreg.QueryInfoKey(key)[0]):
         skey_name = winreg.EnumKey(key, i)
         skey = winreg.OpenKey(key, skey_name)
         for j in range(0, winreg.QueryInfoKey(skey)[0]):
          sskey_name = winreg.EnumKey(skey, j)
          sskey = winreg.OpenKey(skey, sskey_name)
          try:
           call.tencontent.append(winreg.QueryValueEx(sskey, 'FriendlyName')[0])
          except OSError as e:
              if e.errno == errno.ENOENT:
                  # DisplayName doesn't exist in this skey
               pass
          finally:
             sskey.Close()


def lip():
 if proc_arch == 'x86' and not proc_arch64:
     arch_keys = {0}
 elif proc_arch == 'x86' or proc_arch == 'amd64':
     arch_keys = {winreg.KEY_WOW64_32KEY, winreg.KEY_WOW64_64KEY}
 else:
     raise Exception("Unhandled arch: %s" % proc_arch)

 for arch_key in arch_keys:
     key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces", 0, winreg.KEY_READ | arch_key)
     for i in range(0, winreg.QueryInfoKey(key)[0]):
         skey_name = winreg.EnumKey(key, i)
         skey = winreg.OpenKey(key, skey_name)
         try:
          epoch=winreg.QueryValueEx(skey, 'LeaseObtainedTime')
          epoch1=epoch[0]
          leasestart=datetime.datetime.fromtimestamp(epoch1).strftime('%Y-%m-%d %H:%M:%S')
          epoch=winreg.QueryValueEx(skey, 'LeaseTerminatesTime')
          epoch1=epoch[0]
          leaseend=datetime.datetime.fromtimestamp(epoch1).strftime('%Y-%m-%d %H:%M:%S')
          call.tencontent.append(winreg.QueryValueEx(skey, 'DhcpIPAddress')[0]+"    "+leasestart+"    "+leaseend)
           #call.tencontent.append("        ")
           #call.tencontent.append(leasestart)
           #call.tencontent.append("        ")
           #call.tencontent.append(leaseend)
         except OSError as e:
            if e.errno == errno.ENOENT:
                # DisplayName doesn't exist in this skey
             pass
         finally:
             print("passed this")
     for i in range(0, winreg.QueryInfoKey(key)[0]):
         skey_name = winreg.EnumKey(key, i)
         skey = winreg.OpenKey(key, skey_name)		 
         for j in range(0, winreg.QueryInfoKey(skey)[0]):
           sskey_name = winreg.EnumKey(skey, j)
           sskey = winreg.OpenKey(skey, sskey_name)
           try:
            epoch=winreg.QueryValueEx(sskey, 'LeaseObtainedTime')
            epoch1=epoch[0]
            leasestart=datetime.datetime.fromtimestamp(epoch1).strftime('%Y-%m-%d %H:%M:%S')
            epoch=winreg.QueryValueEx(sskey, 'LeaseTerminatesTime')
            epoch1=epoch[0]
            leaseend=datetime.datetime.fromtimestamp(epoch1).strftime('%Y-%m-%d %H:%M:%S')
            call.tencontent.append(winreg.QueryValueEx(sskey, 'DhcpIPAddress')[0]+"    "+leasestart+"    "+leaseend)
           except OSError as e:
             if e.errno == errno.ENOENT:
                 # DisplayName doesn't exist in this skey
              pass
           finally:
             print("passed this sub")


def lwin():
     
    hKey = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,"Software\\Microsoft\\Windows NT\\CurrentVersion")
    values = {"ProductName", "RegisteredOwner", "CurrentBuildNumber", "SystemRoot" }                     
    for  i in values:
         r= winreg.QueryValueEx(hKey, i)
         call.tencontent.append(i +"             :           "+ str(r[0]))
	 
def lregentry():

             task=os.popen('reg query HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Applets\Regedit').read()
             z=task.split('\n')
             y=z[-3].split(' ')
             call.tencontent.append(y[-1])
			 
def lrecfile():
    
    for i in range(1,150):
     z = "reg query HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs" + " /v " + str(i)
     task=os.popen(z).read()
     task1=task.split(' ')
     
     y=bytes.fromhex(task1[-1]).decode('utf-16')
     #print(y)
     new = y[0:36]
     call.tencontent.append(new)
	 #k =re.search(r"\w.\w\w\w",y)
     #print(k)

def lstart():
 task=os.popen('reg query HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run').read()
 #print(task)
 x=str(task)
 x=x.replace("HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run"," ")
 call.tencontent.append(x.replace("REG_SZ"," "))
 
def luserinfo():
 if proc_arch == 'x86' and not proc_arch64:
     arch_keys = {0}
 elif proc_arch == 'x86' or proc_arch == 'amd64':
     arch_keys = {winreg.KEY_WOW64_32KEY, winreg.KEY_WOW64_64KEY}
 else:
     raise Exception("Unhandled arch: %s" % proc_arch)
 userlist = []
 for arch_key in arch_keys:
     key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList", 0, winreg.KEY_READ | arch_key)
     for i in range(0, winreg.QueryInfoKey(key)[0]):
         skey_name = winreg.EnumKey(key, i)
         skey = winreg.OpenKey(key, skey_name)
         try:
           (value, type)=winreg.QueryValueEx(skey, 'ProfileImagePath')
           #print(epoch)
           #print(type(epoch))
           user = value.split('\\')[-1]
           userlist.append(user)
         except OSError as e:
              if e.errno == errno.ENOENT:
                  # DisplayName doesn't exist in this skey
               pass
         finally:
             skey.Close()
 userlist = list(dict.fromkeys(userlist))
 for i in userlist:
  call.tencontent.append(i)


def lastrun():
      final=[]
      z = "reg query HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" 
      task=os.popen(z).read()     
      nn=task.split('\n')
      for i in nn:
       y=i.split('\\')
       print(y)
       final.append(str(y[0].split(" ")[-1]))
       #call.tencontent.append(y[0])
      del final[:2]
      for i in final:
       call.tencontent.append(i)

def lastlogin():
      final=[]
      z = "reg query HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" 
      task=os.popen(z).read()     
      nn=task.split('\n')
      for i in nn:
       y=i.split('\\')
       print(y)
       final.append(str(y[0].split(" ")[-1]))
       #call.tencontent.append(y[0])
      del final[:2]
      for i in final:
       call.tencontent.append(i)

def lsysinfo():
 proc=["\\0 /v Identifier","\\0 /v ProcessorNameString","\\0 /v VendorIdentifier"]
 for i in proc:
     z = "reg query HKEY_LOCAL_MACHINE\HARDWARE\DESCRIPTION\System\CentralProcessor"+ str(i)
     #print(z)
     task=os.popen(z).read()
     #print(task)
     task1=str(task).replace('REG_SZ',' ')
     task1 = task1.replace("HKEY_LOCAL_MACHINE\HARDWARE\DESCRIPTION\System\CentralProcessor\\0","")
     call.tencontent.append(task1)
	 
	 
	 
#------------------------------Above is live mama---------------------------------------------------
#------------------------------Below will be dead one mama------------------------------------------
 
 
def dusb():
   call.tencontent.setText(call.tenarti.currentText())
   #SYSTEM\CurrentControlSet\Enum\USBSTOR FriendlyName
   #reg = RegistryHive(file+"/SYSTEM")
   #print(reg.get_key('Software\\Microsoft\\Windows NT\\CurrentVersion').get_subkey())
   #for entry in reg.recurse_subkeys(as_json=True):
    #print(entry)
   
def dapps():
   call.tencontent.setText(call.tenarti.currentText())
   
   
def drecfile():
   call.tencontent.setText(call.tenarti.currentText())
   
   
def dregentry():
   call.tencontent.setText(call.tenarti.currentText())
   
   
def dwin():
   call.tencontent.setText(call.tenarti.currentText())
   
   
def dstart():
   call.tencontent.setText(call.tenarti.currentText())
   
   
def dastrun():
   call.tencontent.setText(call.tenarti.currentText())
   
   
def dip():
   call.tencontent.setText(call.tenarti.currentText())
   
   
def dsysinfo():
   call.tencontent.setText(call.tenarti.currentText())
   
   
def duserinfo():
   call.tencontent.setText(call.tenarti.currentText())
   
   
 
 
def articlicked():
   #what = call.tenarti.currentText()
   #print(what)
   #call.tencontent.setText(what)
   live="live"
   dead="dead"
   print(livedeadidentifier)
   if  livedeadidentifier == live :
      if call.tenarti.currentText() == "USB\'s Connected" :
         call.tencontent.setText("<font size='8' color='red'>Previously connected USB Names</font>")
         lusb()
      elif call.tenarti.currentText() == "Installed Applications" :
         call.tencontent.setText("--------------------------------------------------------------------------------------------------------")
         lapps()
      elif call.tenarti.currentText() == "Recent Files" :
         call.tencontent.setText("<font size='4' color='red'>recent files</font>")
         lrecfile()
      elif call.tenarti.currentText() == "Last edited registry key" :
         call.tencontent.setText("<font size='4' color='red'>Last edited registry Entry</font>")
         lregentry()
      elif call.tenarti.currentText() == "Windows's Information" :
         call.tencontent.setText("<font size='8' color='red'>Windows Information</font>")
         lwin()
      elif call.tenarti.currentText() == "Startup Apps" :
         call.tencontent.setText("<font size='8' color='red'>Startup Apps                      Location</font>")
         lstart()
      elif call.tenarti.currentText() == "Last Run Command" :
         call.tencontent.setText("<font size='4' color='red'>Last Run Command</font>")
         lastrun()
      elif call.tenarti.currentText() == "IP\'information" :
         call.tencontent.setText("<font size='8' color='red'>Set of IP's assigned to device</font>")
         lip()
      elif call.tenarti.currentText() == "System info" :
         call.tencontent.setText("<font size='4' color='red'>System Info</font>")
         lsysinfo()
      elif call.tenarti.currentText() == "User Information" :
         call.tencontent.setText("<font size='8' color='red'>Users on system</font>")
         luserinfo()
   else:
      if call.tenarti.currentText() == "USB\'s Connected" :
         call.tencontent.setText("<font size='8' color='red'>Previously connected USB Names</font>")
         dusb()
      elif call.tenarti.currentText() == "Installed Applications" :
         call.tencontent.setText("--------------------------------------------------------------------------------------------------------")
         dapps()
      elif call.tenarti.currentText() == "Recent Files" :
         call.tencontent.setText("<font size='4' color='red'>recent files</font>")
         drecfile()
      elif call.tenarti.currentText() == "Last edited registry key" :
         call.tencontent.setText("<font size='4' color='red'>Last edited registry Entry</font>")
         dregentry()
      elif call.tenarti.currentText() == "Windows's Information" :
         call.tencontent.setText("<font size='8' color='red'>Windows Information</font>")
         dwin()
      elif call.tenarti.currentText() == "Startup Apps" :
         call.tencontent.setText("<font size='8' color='red'>Startup Apps                      Location</font>")
         dstart()
      elif call.tenarti.currentText() == "Last Run Command" :
         call.tencontent.setText("<font size='4' color='red'>Last Run Command</font>")
         dastrun()
      elif call.tenarti.currentText() == "IP\'information" :
         call.tencontent.setText("<font size='8' color='red'>Set of IP's assigned to device</font>")
         dip()
      elif call.tenarti.currentText() == "System info" :
         call.tencontent.setText("<font size='4' color='red'>System Info</font>")
         dsysinfo()
      elif call.tenarti.currentText() == "User Information" :
         call.tencontent.setText("<font size='8' color='red'>Users on system</font>")
         duserinfo()

def livedeadcheck():
   global livedeadidentifier
   if call.livedead.currentText() == "Live Forensics":
      call.tencontent.setText("live one")
      livedeadidentifier="live"
   else:
      global file
      file = str(QFileDialog.getExistingDirectory(call, "Select Directory"))
      print(file)
      call.tencontent.setText("dead one")
      livedeadidentifier="dead"


app=QtWidgets.QApplication([])
call=uic.loadUi("girainterface.ui")

livedeadidentifier=call.fileok.clicked.connect(livedeadcheck)
print(livedeadidentifier)
call.tenartigo.clicked.connect(articlicked)


call.show()
app.exec()

