from tkinter import *
from tkinter import scrolledtext
from tkinter import messagebox
from tkinter import filedialog
from subprocess import Popen, PIPE
from shutil import move
import platform
import json
import os
import ast

walletTitle = 'Personal Secure Wallet'
walletVersion = '0.1'
walletAuthor = 'Ronivon Costa (2021) ronivon.costa@gmail.com'
passphrase = ''
isObfuscated = False
walletContent = ''
socialContent = ''
ecommContent = ''
projContent = ''
othercontent = ''
view = 'social'
walletFileName = ''

configData = {'encryptionToool': {'openssl': {'walletPoweredBy': 'OpenSSL', 'encryptionCommand': ['/usr/bin/openssl', 'enc', '-aes-256-ecb', '-a'], 'decryptionCommand': ['/usr/bin/openssl', 'enc', '-aes-256-ecb', '-a', '-d'], 'encryptParam': '-k', 'decryptParam': '-k', 'fileOutParam': '-out', 'fileInParam': '-in', 'myFileTypes': '(("AES files", "*.aes"), ("Backup files", "*.bak"), ("All files", "*"))'}, '7-zip': {'walletPoweredBy': '7-Zip', 'encryptionCommand': ['C:\\Program Files\\7-Zip\\7z.exe', 'a', '-aoa', '-t7z', '-m0=lzma2', '-mx=9', '-mfb=64', '-md=32m', '-ms=on', '-mhe=on', '-si'], 'decryptionCommand': ['C:\\Program Files\\7-Zip\\7z.exe', 'x', '-so'], 'encryptParam': '-p%', 'decryptParam': '-p%', 'fileOutParam': '', 'fileInParam': '', 'myFileTypes': '(("7-Zip files", "*.7z"), ("Backup files", "*.bak"), ("All files", "*"))'}}}
if platform.system() == 'Windows':
    walletPoweredBy = '7-zip'
else:
    walletPoweredBy = 'openssl'

def showVersion():
    global configData
    global walletPoweredBy
    pInfo = 'Version ' + walletVersion + '\n'
    pInfo = pInfo + 'Powered by ' + configData['encryptionToool'][walletPoweredBy]['walletPoweredBy'] + '\n'
    pInfo = pInfo + walletAuthor 
    messagebox.showinfo(walletTitle, pInfo)

def validatePass(parentwindow, pass1, pass2):
    global passphrase
    if pass1 == pass2:
        if len(pass1) > 0:
            passphrase = pass1
            #messagebox.showinfo('Success', 'Passphrase Set')
            parentwindow.destroy()
        else:
            passphrase = ''
            parentwindow.destroy()
    else:
        messagebox.showinfo('Failed', 'Passphrases does not match')

def setPass():
    passwindow = Tk()
    passwindow.title('Set Passphrase for Wallet')
    passwindow.geometry('370x65')
    passlbl1 = Label(passwindow, text = 'Passphrase:')
    passlbl1.grid(column = 0, row = 0)
    passlbl2 = Label(passwindow, text = 'Confirm:')
    passlbl2.grid(column = 0, row = 1)

    passfield1 = Entry(passwindow, show = '*', width = 25)
    passfield2 = Entry(passwindow, show = '*', width = 25)
    passfield1.grid(column = 1, row = 0)
    passfield2.grid(column = 1, row = 1)
    passfield1.focus()

    btn = Button(passwindow, text = 'Set', command = lambda: validatePass(passwindow, passfield1.get(), passfield2.get()))
    btn.grid(column = 2, row = 1)
    passfield1.bind('<Return>', lambda event: passfield2.focus())
    passfield2.bind('<Return>', lambda event: validatePass(passwindow, passfield1.get(), passfield2.get()))


def openWallet():
    global passphrase
    global isObfuscated
    global socialContent
    global ecommContent
    global projContent
    global otherContent
    global configData
    global walletPoweredBy
    global walletFileName

    decryptParam = configData['encryptionToool'][walletPoweredBy]['decryptParam']
    fileInParam = configData['encryptionToool'][walletPoweredBy]['fileInParam']
    myFileTypes = ast.literal_eval(configData['encryptionToool'][walletPoweredBy]['myFileTypes'])
    loadCommand = configData['encryptionToool'][walletPoweredBy]['decryptionCommand'][:]
    successLoad = False

    walletName = filedialog.askopenfilename(filetypes = myFileTypes)

    if len(passphrase) == 0:
        try:
            with open(walletName, 'r') as fileIn:
                fileContent = json.loads(fileIn.read())
                socialContent = fileContent["data"]["social"]
                ecommContent = fileContent["data"]["ecommerce"]
                projContent = fileContent["data"]["projects"]
                otherContent = fileContent["data"]["others"]
                successLoad = True
        except Exception as e:
            messagebox.showerror('Failed', str(e))
    else:
        if '%' in decryptParam:
            decryptParm = decryptParam.replace('%',passphrase)
            loadCommand.append(decryptParm)
        else:  
            loadCommand.append(decryptParam)
            loadCommand.append(passphrase)
        
        if len(fileInParam) > 0:
            loadCommand.append(fileInParam)

        loadCommand.append(walletName)

        try:
            process = Popen(loadCommand, stdout=PIPE, stderr=PIPE)
            (fc, err) = process.communicate()
            exit_code = process.wait()
            if exit_code != 0:
                if 'bad decrypt' in str(err).lower() or 'error' in str(err).lower or 'wrong pass' in str(err).lower(): 
                    messagebox.showerror('Failed', 'Passphrase is incorrect ot this is not a valid Wallet file.')
                else:
                    messagebox.showerror('Failed', 'Could not open or decrypt the file.')
            else:
                fileContent = json.loads(fc.decode())
                socialContent = fileContent["data"]["social"]
                ecommContent = fileContent["data"]["ecommerce"]
                projContent = fileContent["data"]["projects"]
                otherContent = fileContent["data"]["others"]
                successLoad = True

        except Exception as e:
            messagebox.showerror('Failed', str(e))

    if successLoad:
        walletFileName = walletName
        root.title("Personal Safe Wallet:"+walletFileName.rpartition('/')[2])
        if isObfuscated == False:
            textSocial.delete('1.0', END)
            texteComm.delete('1.0', END)
            textProj.delete('1.0', END)
            textOthers.delete('1.0', END)

            textSocial.insert('1.0', socialContent)
            texteComm.insert('1.0', ecommContent)
            textProj.insert('1.0', projContent)
            textOthers.insert('1.0', otherContent)

def saveAsWallet():
    global configData
    global walletPoweredBy

    myFileTypes = ast.literal_eval(configData['encryptionToool'][walletPoweredBy]['myFileTypes'])
    walletName = filedialog.asksaveasfilename(filetypes = myFileTypes)

    saveWallet(walletName)

def saveWallet(walletName):
    global passphrase
    global isObfuscated
    global socialContent
    global ecommContent
    global projContent
    global otherContent
    global configData
    global walletPoweredBy
    global walletFileName

    if walletName == '':
        myFileTypes = ast.literal_eval(configData['encryptionToool'][walletPoweredBy]['myFileTypes'])
        walletName = filedialog.asksaveasfilename(filetypes = myFileTypes)
    else:
        walletFileName = walletName

    if len(passphrase) == 0:
        messagebox.showwarning('Attention', 'Passphrase is not set - this file will be saved in plain text.\nTo encrypt the file on disk, set the passphrase before saving it.')

    if os.path.isfile(walletName):
        try:
            move(walletName, walletName+'.bak')
        except Exception as e:
            messagebox.showerror('Failed', 'Failed to backup current wallet.\nSave using a different name.\n'+str(e))
            return

    encryptParam = configData['encryptionToool'][walletPoweredBy]['encryptParam']
    fileOutParam = configData['encryptionToool'][walletPoweredBy]['fileOutParam']
    saveCommand = configData['encryptionToool'][walletPoweredBy]['encryptionCommand'][:]

    walletContent = {}
    walletContent["config"] = {}
    walletContent["data"] = {}

    if textSocial.get('end-1c', 'end') == '\n':
        textSocial.delete('end-1c', 'end')
    if texteComm.get('end-1c', 'end') == '\n':
        texteComm.delete('end-1c', 'end')
    if textProj.get('end-1c', 'end') == '\n':
        textProj.delete('end-1c', 'end')
    if textOthers.get('end-1c', 'end') == '\n':
        textOthers.delete('end-1c', 'end')

    if len(passphrase) == 0:
        try:
            if isObfuscated == False:
                fileContent1 = textSocial.get('1.0', END)
                fileContent2 = texteComm.get('1.0', END)
                fileContent3 = textProj.get('1.0', END)
                fileContent4 = textOthers.get('1.0', END)
            else:
                fileContent1 = socialContent[:]
                fileContent2 = ecommContent[:]
                fileContent3 = projContent[:]
                fileContent4 = otherContent[:]

            walletContent["data"]["social"] = fileContent1
            walletContent["data"]["ecommerce"] = fileContent2
            walletContent["data"]["projects"] = fileContent3
            walletContent["data"]["others"] = fileContent4

            with open(walletName, 'a') as fileOut:
                fileOut.write(json.dumps(walletContent))
                successSave = True

        except Exception as e:
            messagebox.showerror('Failed', str(e))
    else:
        try:
            if isObfuscated == False:
                fileContent1 = textSocial.get('1.0', END)
                fileContent2 = texteComm.get('1.0', END)
                fileContent3 = textProj.get('1.0', END)
                fileContent4 = textOthers.get('1.0', END)
            else:
                fileContent1 = socialContent[:]
                fileContent2 = ecommContent[:]
                fileContent3 = projContent[:]
                fileContent4 = otherContent[:]

            walletContent["data"]["social"] = fileContent1
            walletContent["data"]["ecommerce"] = fileContent2
            walletContent["data"]["projects"] = fileContent3
            walletContent["data"]["others"] = fileContent4

            if '%' in encryptParam:
                cryptParm = encryptParam.replace('%',passphrase)
                saveCommand.append(cryptParm)
            else:  
                saveCommand.append(encryptParam)
                saveCommand.append(passphrase)
            
            if len(fileOutParam) > 0:
                saveCommand.append(fileOutParam)

            saveCommand.append(walletName)
  
            process = Popen(saveCommand, stdout=PIPE, stdin=PIPE, stderr=PIPE)
            processoutput = process.communicate(input = bytes(json.dumps(walletContent), "utf-8"))
            exit_code = process.wait()
            if exit_code == 0:
                successSave = True
                messagebox.showinfo('Success', 'File Saved.')
            else:
                messagebox.showerror('Failed', str(process) + ' - ' + str(processoutput))

        except Exception as e:
            messagebox.showerror('Failed Exception', str(e))

    if successSave == True:
        walletFileName = walletName
        root.title("Personal Safe Wallet:"+walletFileName.rpartition('/')[2])

def toggleView(oper):
    global isObfuscated
    global socialContent
    global ecommContent
    global projContent
    global otherContent
    global view
    
    if oper == 'obfs':
        if isObfuscated == False:
            socialContent = textSocial.get('1.0', END).strip()
            ecommContent = texteComm.get('1.0', END).strip()
            projContent = textProj.get('1.0', END).strip()
            otherContent = textOthers.get('1.0', END).strip()

            isObfuscated = True
            textSocial.delete('1.0', END)
            texteComm.delete('1.0', END)
            textProj.delete('1.0', END)
            textOthers.delete('1.0', END)
            for line in socialContent.splitlines():
                textSocial.insert('1.0', '*' * len(line) + '\n')
            for line in ecommContent.splitlines():
                texteComm.insert('1.0', '*' * len(line) + '\n')
            for line in projContent.splitlines():
                textProj.insert('1.0', '*' * len(line) + '\n')
            for line in otherContent.splitlines():
                textOthers.insert('1.0', '*' * len(line) + '\n')

            textSocial.configure(state = 'disabled')
            texteComm.configure(state = 'disabled')
            textProj.configure(state = 'disabled')
            textOthers.configure(state = 'disabled')
        else:
            textSocial.configure(state = 'normal')
            textSocial.delete('1.0', END)
            textSocial.insert('1.0', socialContent)
            texteComm.configure(state = 'normal')
            texteComm.delete('1.0', END)
            texteComm.insert('1.0', ecommContent)
            textProj.configure(state = 'normal')
            textProj.delete('1.0', END)
            textProj.insert('1.0', projContent)
            textOthers.configure(state = 'normal')
            textOthers.delete('1.0', END)
            textOthers.insert('1.0', otherContent)
            isObfuscated = False
    elif oper == view:
        pass
    else:
        
        if view == 'social':
            textGroupSocial.grid_remove()
        elif view == 'ecomm':
            textGroupeComm.grid_remove()
        elif view == 'projects':
            textGroupProj.grid_remove()
        elif view == 'others':
            textGroupOthers.grid_remove()
        
        if oper == 'social':
            textGroupSocial.grid()
        elif oper == 'ecomm':
            textGroupeComm.grid()
        elif oper == 'projects':
            textGroupProj.grid()
        elif oper == 'others':
            textGroupOthers.grid()

        view = oper
        
def setPoweredBy(toolChoice):
    global walletPoweredBy
    walletPoweredBy = toolChoice

def setOptions():
    global configData

    optVar = StringVar()

    optionsWindow = Tk()
    optionsWindow.title('Options')
    optionsWindow.geometry('200x100')

    encAppLabel = Label(optionsWindow, text = 'Select encryption software:')
    encAppLabel.grid(column = 0, row = 0, columnspan = 3, sticky = E+W+N+S)

    encAppOpt1 = Radiobutton(optionsWindow, text = "7-Zip", variable = optVar, value = '7-zip', command = lambda: setPoweredBy('7-zip'))
    encAppOpt1.grid(column = 1, row = 2, sticky = E+W+N+S)
    encAppOpt2 = Radiobutton(optionsWindow, text = "OpenSSL", variable = optVar, value = 'openssl', command = lambda: setPoweredBy('openssl'))
    encAppOpt2.grid(column = 1, row = 1, sticky = E+W+N+S)

    encAppClose = Button(optionsWindow, text = "Close", command = optionsWindow.destroy)
    encAppClose.grid(column = 1, row = 3)

    if walletPoweredBy == 'openssl':
        encAppOpt2.select()
    elif walletPoweredBy == '7-zip':
        encAppOpt1.select()

root = Tk()
root.title("Personal Safe Wallet "+walletFileName)
root.geometry('500x200')

menuOptions = Menu(root)
root.config(menu = menuOptions)

filemenu = Menu(menuOptions, tearoff = 0)
filemenu.add_command(label='Open...', command = openWallet)
filemenu.add_command(label='Save', command = lambda: saveWallet(walletFileName))
filemenu.add_command(label='Save As...', command = saveAsWallet)
menuOptions.add_cascade(label='File', menu = filemenu)

configmenu = Menu(menuOptions, tearoff = 0)
configmenu.add_command(label='Passphrase', command = setPass)
configmenu.add_command(label='Options', command = setOptions)
menuOptions.add_cascade(label='Edit', menu = configmenu)

windowmenu = Menu(menuOptions, tearoff = 0)
windowmenu.add_command(label='Hide/View Secrets', command = lambda: toggleView('obfs'))
windowmenu.add_command(label='Social', command = lambda: toggleView('social'))
windowmenu.add_command(label='eCommerce', command = lambda: toggleView('ecomm'))
windowmenu.add_command(label='Projects', command = lambda: toggleView('projects'))
windowmenu.add_command(label='Other Secrets', command = lambda: toggleView('others'))
menuOptions.add_cascade(label='View', menu = windowmenu)

aboutmenu = Menu(menuOptions, tearoff = 0)
aboutmenu.add_command(label='Version', command = showVersion)
menuOptions.add_cascade(label='About', menu = aboutmenu)

textGroupeComm = LabelFrame(root, text = 'e-Commerce & Buy Web sites', padx = 5, pady = 5)
textGroupeComm.grid(row = 1, column = 0, columnspan = 3, padx = 10, pady = 10)
textGroupeComm.rowconfigure(0, weight = 1)
textGroupeComm.columnconfigure(0, weight = 1)

textGroupProj = LabelFrame(root, text = 'Projects & Clients', padx = 5, pady = 5)
textGroupProj.grid(row = 1, column = 0, columnspan = 3, padx = 10, pady = 10)
textGroupProj.rowconfigure(0, weight = 1)
textGroupProj.columnconfigure(0, weight = 1)

textGroupOthers = LabelFrame(root, text = 'Other Secrets', padx = 5, pady = 5)
textGroupOthers.grid(row = 1, column = 0, columnspan = 3, padx = 10, pady = 10)
textGroupOthers.rowconfigure(0, weight = 1)
textGroupOthers.columnconfigure(0, weight = 1)

root.columnconfigure(0, weight = 1)
root.rowconfigure(1, weight = 1)

texteComm = scrolledtext.ScrolledText(textGroupeComm, height=10)
textProj = scrolledtext.ScrolledText(textGroupProj, height=10)
textOthers = scrolledtext.ScrolledText(textGroupOthers, height=10)

texteComm.grid(column = 0, row = 1)
textProj.grid(column = 0, row = 1)
textOthers.grid(column = 0, row = 1)

textGroupSocial = LabelFrame(root, text = 'e-Mail & Social', padx = 5, pady = 5)
textGroupSocial.grid(row = 1, column = 0, columnspan = 3, padx = 10, pady = 10)
textGroupSocial.rowconfigure(0, weight = 1)
textGroupSocial.columnconfigure(0, weight = 1)

textSocial = scrolledtext.ScrolledText(textGroupSocial, height=10)
textSocial.grid(column = 0, row = 1)

toggleView('others')
toggleView('projects')
toggleView('ecomm')
toggleView('social')

root.mainloop()

