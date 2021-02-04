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
walletAuthor = 'Ronivon Costa (2021), ronivon.costa@gmail.com'
passphrase = ''
isObfuscated = False
walletContent = ''
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

def openWallet():
    global passphrase
    global isObfuscated
    global walletContent
    global configData
    global walletPoweredBy

    decryptParam = configData['encryptionToool'][walletPoweredBy]['decryptParam']
    fileInParam = configData['encryptionToool'][walletPoweredBy]['fileInParam']
    myFileTypes = ast.literal_eval(configData['encryptionToool'][walletPoweredBy]['myFileTypes'])
    loadCommand = configData['encryptionToool'][walletPoweredBy]['decryptionCommand'][:]
    successLoad = False

    walletName = filedialog.askopenfilename(filetypes = myFileTypes)

    if len(passphrase) == 0:
        try:
            with open(walletName, 'r') as fileIn:
                walletContent = fileIn.read()
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
            (walletContent, err) = process.communicate()
            exit_code = process.wait()
            if exit_code != 0:
                if 'bad decrypt' in str(err).lower() or 'error' in str(err).lower or 'wrong pass' in str(err).lower(): 
                    messagebox.showerror('Failed', 'Passphrase is incorrect ot this is not a valid Wallet file.')
                else:
                    messagebox.showerror('Failed', 'Could not open or decrypt the file.')
            else:
                successLoad = True

        except Exception as e:
            messagebox.showerror('Failed', str(e))

    if successLoad:
        if isObfuscated == False:
            txt.delete('1.0', END)
            txt.insert('1.0', walletContent)


def saveWallet():
    global passphrase
    global isObfuscated
    global walletContent
    global configData
    global walletPoweredBy
    
    encryptParam = configData['encryptionToool'][walletPoweredBy]['encryptParam']
    fileOutParam = configData['encryptionToool'][walletPoweredBy]['fileOutParam']
    myFileTypes = ast.literal_eval(configData['encryptionToool'][walletPoweredBy]['myFileTypes'])
    saveCommand = configData['encryptionToool'][walletPoweredBy]['encryptionCommand'][:]

    if len(passphrase) == 0:
        messagebox.showwarning('Attention', 'Passphrase is not set - this file will be saved in plain text.\nTo encrypt the file on disk, set the passphrase before saving it.')

    walletName = filedialog.asksaveasfilename(filetypes = myFileTypes)
    if os.path.isfile(walletName):
        try:
            move(walletName, walletName+'.bak')
        except Exception as e:
            messagebox.showerror('Failed', 'Failed to backup current wallet.\nSave using a different name.\n'+str(e))
            return

    if len(passphrase) == 0:
        try:
            if isObfuscated == False:
                walletContent = txt.get('1.0', END)

            with open(walletName, 'a') as fileOut:
                fileOut.write(walletContent)
        except Exception as e:
            messagebox.showerror('Failed', str(e))
    else:
        try:
            if isObfuscated == False:
                fileContent = bytes(txt.get('1.0', END), encoding = 'utf-8')
            else:
                fileContent = bytes(walletContent[:], encoding = 'utf-8')
    
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
            processoutput = process.communicate(input = fileContent)[0]
            exit_code = process.wait()
            if exit_code == 0:
                messagebox.showinfo('Success', 'File Saved.')
            else:
                messagebox.showerror('Failed', str(process) + ' - ' + str(processoutput))

        except Exception as e:
            messagebox.showerror('Failed Exception', str(e))

def toggleObfuscation():
    global isObfuscated
    global walletContent

    if isObfuscated == False:
        walletContent = txt.get('1.0', END).strip()
        isObfuscated = True
        txt.delete('1.0', END)
        for line in walletContent.splitlines():
            txt.insert('1.0', '*' * len(line) + '\n')

        txt.configure(state = 'disabled')
    else:
        txt.configure(state = 'normal')
        txt.delete('1.0', END)
        txt.insert('1.0', walletContent)
        isObfuscated = False

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
root.title("Personal Safe Wallet")
root.geometry('350x440')

menuOptions = Menu(root)
root.config(menu = menuOptions)

filemenu = Menu(menuOptions, tearoff = 0)
filemenu.add_command(label='Open...', command = openWallet)
filemenu.add_command(label='Save As...', command = saveWallet)
menuOptions.add_cascade(label='File', menu = filemenu)

configmenu = Menu(menuOptions, tearoff = 0)
configmenu.add_command(label='Passphrase', command = setPass)
configmenu.add_command(label='Options', command = setOptions)
menuOptions.add_cascade(label='Edit', menu = configmenu)

obfsmenu = Menu(menuOptions, tearoff = 0)
obfsmenu.add_command(label='Hide/View Secrets', command = toggleObfuscation)
menuOptions.add_cascade(label='Window', menu = obfsmenu)

aboutmenu = Menu(menuOptions, tearoff = 0)
aboutmenu.add_command(label='Version', command = showVersion)
menuOptions.add_cascade(label='About', menu = aboutmenu)

textGroup = LabelFrame(root, text = 'Secrets', padx = 5, pady = 5)
textGroup.grid(row = 1, column = 0, columnspan = 3, padx = 10, pady = 10, sticky = E+W+N+S)
textGroup.rowconfigure(0, weight = 1)
textGroup.columnconfigure(0, weight = 1)

root.columnconfigure(0, weight = 1)
root.rowconfigure(1, weight = 1)

txt = scrolledtext.ScrolledText(textGroup)
txt.grid(column = 0, row = 3, sticky = E+W+N+S)

root.mainloop()

