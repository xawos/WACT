#!/usr/bin/env python3
from linereader import copen
from random import randint
from time import sleep
import traceback
import threading
import paramiko
import socket
import sys
import csv
import os

LOG = open("logs/log.txt", "a")
HOST_KEY = paramiko.RSAKey(filename='keys/private.key')
NOPE_FILE = "ascii/nopes.txt"
IAM_FILE = "keys/iam.csv"
PORT = 2222


def send_nope(chan):
    nopefile = copen(NOPE_FILE)
    lines = nopefile.count('\n')
    random_line = nopefile.getline(randint(1, lines))
    chan.send(random_line + "\r")


def handle_cmd(cmd, chan):
    response = ""
    user = chan.get_transport().get_username()
    ip = chan.get_transport().getpeername()
    if cmd.startswith("cheese"):
        response = user + "@" + str(ip[0])
    elif cmd.startswith("cat"):
        # Checks for auth and then send the TXT file line by line
        catfile = cmd[3:].lstrip()
        if check_auth_file(user, catfile):
            if os.path.isfile("files/{}".format(catfile)):
                send_file(catfile, chan)
            else:
                send_nope(chan)
                response = catfile + " does not exist for real, ma bruh"
        else:
            if os.path.isfile("files/{}".format(catfile)):
                response = "\r\nNo touchy! Just watchy!\r\n"
            elif catfile == "":
                send_ascii("cat.txt", chan)
                return
            else:
                response = "cat: '{}': No such file or directory".format(catfile)
    elif cmd.startswith("ls"):
        if cmd != "ls":
            chan.send("No parameters allowed, bailing to default ls: \r\n")
        arr = os.listdir('files/')
        ls = ""
        sortarr = sorted(arr)
        for i in sortarr:
            ls += i + "\t"
        response = ls
    elif cmd.startswith("cd"):
        send_ascii("cd.txt", chan)
        response = "\r\nNo folders here, anyway here's a CD"
    elif cmd.startswith("version"):
        response = "1.3.3.7"
    elif cmd.startswith("answer"):
        response = "42"
    elif cmd.startswith("pwd"):
        response = "You're in a weird place"
    elif cmd.startswith("sudo"):
        send_ascii("sudo.txt", chan)
        return
    elif cmd == "tac":
        send_ascii("cat.txt", chan)
        return
    elif cmd == "rm -rf /":
        send_ascii("bomb.txt", chan)
        response = "Yeah Yeah, sure."
    elif cmd.startswith("rm"):
        response = "Permission denied."
    elif cmd.startswith("whoami") | cmd.startswith("id"):
        send_ascii("wizard.txt", chan)
        response = "You are a wizard of the internet!"
    elif ".exe" in cmd:
        response = ".exe files? Your methods are unconventional."
    elif cmd.startswith("cmd") | cmd.startswith("ps1") | cmd.startswith("dir"):
        response = "Where do you think you are? We only use respectable OSs.. Sorry"
    elif cmd == "hack":
        if user == "shadow":
            send_ascii("shadow.txt", chan)
            return
        send_ascii("clippy.txt", chan)
        return
    elif cmd == "help":
        send_ascii("help.txt", chan)
        response = "bash: help: command not found \r\n Try 'halp' instead"
    elif cmd == "halp":
        # Only the last user will have access to.. something, for now surely a new `halp` page
        if user == "shadow":
            send_ascii("shadow.txt", chan)
            return
        send_ascii("halp.txt", chan)
        return
    elif cmd.startswith("bash"):
        response = "You silly, of course this is not bash ;)"
    elif cmd == ":(){:|:&};:":
        for i in range(8):
            chan.send("-bash: fork: retry: Resource temporarily unavailable\r\n")
            sleep(0.25)
        chan.send("\r\nJust kidding, you wish..\r\n\r\n")
        return
    elif cmd == "destroy_penguins()":
        response = "Not yet, sorry :("
    elif cmd.__len__() == 0:
        return
    else:
        send_nope(chan)
        response = "Use the 'help' command or try crying, maybe"

    LOG.write(ip[0] + ": " + cmd + "\n")
    LOG.flush()
    chan.send(response + "\r\n")


def handle_admin(cmd, chan):
    if cmd.startswith("!"):
        # Commands starting with `!` will execute 
        cexe = cmd[1:].lstrip()
        response = str(eval(cexe))
    elif cmd.startswith("$"):
        # Commands starting with `$` will show the `dir()` of the object specified
        dexe = cmd[1:].lstrip()
        try:
            for item in dir(eval(dexe)):
                chan.send(str(item) + "\r")
        except Exception as e:
            print(e)
            response = "ke"
    elif cmd.startswith("wget "):
        wexe = cmd[4:].lstrip()
        send_admin(wexe)
        # Yeah, I know, it's dangerous, but it's admin. It even has a password.
        # Saved in a CSV in cleartext. I've made all the possible security decisions wrong.
    else:
        # bail to default handler
        handle_cmd(cmd, chan)

# Simply send a file line by line
def send_something(folder, file, chan):
    with open(folder + "/" + file) as thingy:
        chan.send("\r")
        for line in enumerate(thingy):
            chan.send(line[1] + "\r")

# The following 3 functions are just wrappers for the above one
def send_admin(file, chan):
    send_something(".", file, chan)


def send_file(file, chan):
    send_something("files", file, chan)


def send_ascii(file, chan):
    send_something("ascii", file, chan)


def check_auth_file(user, filename):
    # Ugly Auth via CSV file, checking first (user) and third (files) 
    # fieldsi in the IAM_FILE for a match. The files are split by a `:`
    with open(IAM_FILE, 'r') as csvfile:
        csv_reader = csv.reader(csvfile)
        for row in csv_reader:
            if row[0] == user:
                for file in row[2].split(":"):
                    if file == filename:
                        return True
    return False


class FakeSshServer(paramiko.ServerInterface):
    def __init__(self):
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        # Checks the IAMFILE for a match between the first and second fields (user/pass)
        with open(IAM_FILE, 'r') as csvfile:
            csv_reader = csv.reader(csvfile)
            for row in csv_reader:
                if row[0] == username and row[1] == password:
                    return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return 'password'

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True


def handle_connection(client, addr):
    try:
        transport = paramiko.Transport(client)
        transport.add_server_key(HOST_KEY)
        transport.local_version = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1"
        # Below here we start the server, with the auth and all, after defining a fake SSH version to trick the client.
        server = FakeSshServer()
        try:
            transport.start_server(server=server)
        except paramiko.SSHException:
            raise Exception("SSH negotiation failed")
        chan = transport.accept(20)
        if chan is None:
            raise Exception("No channel error")

        server.event.wait(10)
        if not server.event.is_set():
            raise Exception("No shell request")

        try:
            user = chan.get_transport().get_username()
            chan.send("\r\nWelcome to the Void, {}\r\n\r\n".format(user))
            # Only the first user (one) will receive the welcome message, no spam allowed in here.
            if user == "zero":
                send_ascii("welcome.txt", chan)
            run = True
            while run:
                chan.send("$ ")
                command = ""
                while not command.endswith("\r"):
                    transport = chan.recv(1024)
                    chan.send(transport)
                    command += transport.decode("utf-8")

                chan.send("\r\n")
                command = command.rstrip()
                print(command)
                if command == "exit":
                    run = False
                # Admin user gets a (very) privileged shell, because yes.
                # It allows him to download virtually any file that the user running the server has.
                # This is due to the "wget" command in "handle_admin" function.
                # Remove that (or the following `elif`) to reduce such exposure
                elif user == "admin":
                    handle_admin(command, chan)
                else:
                    handle_cmd(command, chan)

        except Exception as err:
            print('!!! Exception: {}: {}'.format(err.__class__, err))
            traceback.print_exc()
            try:
                transport.close()
            except Exception:
                pass

        chan.close()

    except Exception as err:
        print('!!! Exception: {}: {}'.format(err.__class__, err))
        traceback.print_exc()
        try:
            transport.close()
        except Exception:
            pass


def start_server():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('', PORT))
    except Exception as err:
        print('*** Bind failed: {}'.format(err))
        traceback.print_exc()
        sys.exit(1)

    threads = []
    while True:
        try:
            sock.listen(100)
            print('Listening for connection ...')
            client, addr = sock.accept()
        except Exception as err:
            traceback.print_exc()
        new_thread = threading.Thread(target=handle_connection, args=(client, addr))
        new_thread.start()
        threads.append(new_thread)
    for thread in threads:
        thread.join()


if __name__ == "__main__":
    start_server()
