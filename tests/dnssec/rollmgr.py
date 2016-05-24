# Copyright (C) 2015 Okami, okami@fuzetsu.info

# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 3
# of the License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.


import fcntl
import os
import socket


# Type of channel we're using.
CHANNEL_TYPE = socket.AF_UNIX
# CHANNEL_TYPE = socket.AF_INET
UNIXSOCK = 'rollmgr.socket'  # Unix socket name.

# there are no TCP ports above 65535,
# thats why original port 880109 is truncated to 16 bits:
# 880109 = 11010110110111101101
#              0110110111101101 = 28141
CMDPORT = 880109 & 0xffff

LINUX_MAXSOCKNAME = 107
MAXSOCKNAME = LINUX_MAXSOCKNAME

ROLLMGR_GROUP = 'g-'
EOL = b'\r\n'  # Net-standard end-of-line.

# The CHANNEL_ entities are used for specifying whether rollmgr_sendcmd()
# should or should not wait for a response from rollerd.
CHANNEL_WAIT = False
CHANNEL_CLOSE = True


class RollMgrMixin(object):
    CLNTSOCK = None
    SOCK = None

    queuedcmds = []

    def rollmgr_dropid(self):
        if self.rollmgr_running():
            return False
        try:
            pidfd = open(self.pidfile or '/run/rollerd.pid', 'w')
            fcntl.flock(pidfd, fcntl.LOCK_EX)
            pidfd.write(str(os.getpid()))
            pidfd.flush()
            fcntl.flock(pidfd, fcntl.LOCK_UN)
            pidfd.close()
        except IOError:
            return False
        else:
            return True

    def rollmgr_channel(self, is_server):
        '''
        Routine: rollmgr_channel()
        Purpose: This routine initializes a socket to use for rollerd
                 communications.  It is called by both rollerd and rollerd
                 clients.

                 Currently, we're only setting up to connect to a rollerd
                 running on our own host.  In time, we may allow remote
                 connections.
        '''
        # Close any previously opened sockets.
        if self.CLNTSOCK:
            self.CLNTSOCK.close()
        if self.SOCK:
            self.SOCK.close()

        if CHANNEL_TYPE == socket.AF_INET:
            # For the server, we'll set the socket's address and mark
            # it as connectable.
            # For the client, we'll get the address of the server and
            # connect to it.  (Right now, we're only talking to localhost.)
            if is_server:
                self.SOCK = socket.socket(
                    socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
                self.SOCK.bind(('localhost', CMDPORT))
                self.SOCK.listen(socket.SOMAXCONN)
            else:
                self.CLNTSOCK = socket.socket(
                    socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
                self.CLNTSOCK.connect(('localhost', CMDPORT))
        elif CHANNEL_TYPE == socket.AF_UNIX:
            # Build the socket name and construct the socket data.
            unixsock = self.sockfile or os.path.join(
                '/run/dnssec-tools', UNIXSOCK)

            # Ensure the socket name isn't too long.  This is a result
            # of a hardcode maximum length for socket names.  This is
            # in the kernel and isn't
            if len(unixsock) > MAXSOCKNAME:
                return -5

            # For the server, we'll create the socket's file and bind it.
            # For the client, we'll get the connect to the server's socket.
            if is_server:
                # Create a Unix domain socket.
                self.SOCK = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM, 0)

                if os.path.exists(unixsock):
                    os.unlink(unixsock)
                self.SOCK.bind(unixsock)
                os.chmod(unixsock, 0o600)
                self.SOCK.listen(socket.SOMAXCONN)
                # flags = fcntl.fcntl(self.SOCK.fileno(), fcntl.F_GETFD)
                # flags |= fcntl.FD_CLOEXEC
                # fcntl.fcntl(self.SOCK.fileno(), fcntl.F_SETFD, flags)
            else:
                # Create and connect to a Unix domain socket.
                self.CLNTSOCK = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM, 0)
                self.CLNTSOCK.connect(unixsock)
        return 1

    def rollmgr_getqueueitem(self):
        '''
        Routine: rollmgr_getqueueitem()
        Purpose: This routine can be called pull a command from the queue
                 This is intended to process the item, so it is removed
                 from the queue.
        '''
        if self.queuedcmds:
            cmd = self.queuedcmds.pop();
            return cmd

    def rollmgr_getid(self):
        return int(next(iter(open(
            self.pidfile or '/run/rollerd.pid', 'r').readlines()), None))

    def rollmgr_running(self):
        '''
        Front-end to the O/S-specific "is rollerd running?" function.
        '''
        try:
            pid = self.rollmgr_getid()
            os.kill(pid, 0)
        except OSError:
            return False
        else:
            return True

    def rollmgr_getcmd(self, waiter=5):
        '''
        This routine is called by the server to fetch a command and
        its data from the command socket.  rollmgr_channel() is
        assumed to have been called to initialize the command socket.
        @param waiter: Time to wait for connect.
        @type waiter: int
        '''
        cmd = b''  # Client's command.
        data = b''  # Command's data.

        # if we have anything queued up, process those first.
        cmdandvalue = self.rollmgr_getqueueitem()
        if cmdandvalue and type(cmdandvalue) == list:
            return

        # Set a time limit on how long we'll wait for the connection.
        self.SOCK.settimeout(waiter)
        try:

            # Accept the waiting connection.
            self.CLNTSOCK, addr = self.SOCK.accept()
            if not self.CLNTSOCK:
                return

            # Do any required domain-specific checks.
            if CHANNEL_TYPE == socket.AF_INET:
                # NOT IMPLEMENTED
                pass
            elif CHANNEL_TYPE == socket.AF_UNIX:
                # Nothing to do now for Unix-domain sockets.
                pass

            # Get the command and data, and lop off the trailing goo.
            def clntsock():
                data = b''
                buf = b'  '  # 2-byted buf
                while buf != EOL:
                    s = self.CLNTSOCK.recv(1)
                    if not s:
                        break
                    buf += s  # push byte into buf
                    data += s  # and into stored data
                    buf = buf[-2:]  # truncate to last 2 bytes
                return data
            cmd = clntsock()[:-3]
            data = clntsock()[:-3]
        except socket.timeout:
            pass

        # Close the remote socket and return the client's data.
        return cmd.decode('utf8'), data.decode('utf8')

    def rollmgr_sendcmd(self, close, cmd, data):
        '''
        Routine: rollmgr_sendcmd()
        Purpose: This routine allows a client to send a message to the server.
                 No other routines need be called to initialize anything.\
        close - Close flag.
        cmd - Command to send.
        data - Data for command.
        '''
        # if not self.rollmgr_verifycmd(cmd):
        #     return False

        # Create the communications channel to rollerd and send the message.
        if self.rollmgr_channel(False) != 1:
            return False

        # Send the command and data.
        self.CLNTSOCK.sendall(cmd.encode('utf8'))
        self.CLNTSOCK.sendall(b' ' + EOL)
        if data:
            self.CLNTSOCK.sendall(data.encode('utf8'))
        self.CLNTSOCK.sendall(b' ' + EOL)
        # self.CLNTSOCK.flush()

        # Select the previous file handle once more.
        # select($oldsel);

        # Close the socket if the client doesn't want a response.
        if close:
            self.CLNTSOCK.close()

        # Let rollerd know there's a command waiting.
        # rollmgr_cmdint();

        return True

    def rollmgr_getresp(self):
        '''
        Routine: rollmgr_getresp()
        Purpose: This routine allows a client to wait for a message response
                 from the server.  It will keep reading response lines until
                 either the socket closes or the timer expires.
        '''
        waiter = 5  # Wait-time for resp.

        # Set a time limit on how long we'll wait for the response.
        # Our alarm handler is a dummy, only intended to keep us from
        # waiting forever.
        self.CLNTSOCK.settimeout(waiter)
        try:
            # Get the response code and message from rollerd.
            def clntsock():
                data = b''
                buf = b'  '  # 2-byted buf
                while buf != EOL:
                    s = self.CLNTSOCK.recv(1)
                    if not s:
                        break
                    buf += s  # push byte into buf
                    data += s  # and into stored data
                    buf = buf[-2:]  # truncate to last 2 bytes
                return data
            retcode = clntsock()[:-3]
            respbuf = clntsock()[:-3]
            return int(retcode), respbuf.decode('utf8')
        except socket.timeout:
            return None, None

    def rollmgr_sendresp(self, retcode, respmsg):
        '''
        This routine allows rollerd to send a message to a client.
        retcode - Return code.
        respmsg - Response message.
        '''
        # Send the return code and response message.
        self.CLNTSOCK.sendall(str(retcode).encode('utf8') + b' ' + EOL)
        self.CLNTSOCK.sendall(respmsg.encode('utf8') + b' ' + EOL)

    def rollmgr_closechan(self):
        '''
        This routine closes down the communications channel to
        rollerd. It is called by both rollerd and rollerd clients.
        '''
        self.CLNTSOCK.close()
