package main

import "net"

// notifyReady tells systemd that serve is ready (sd_notify "READY=1") over
// the datagram socket systemd passed in $NOTIFY_SOCKET; a leading "@" is an
// abstract socket. An empty socket does nothing.
func notifyReady(socket string) error {
	if socket == "" {
		return nil
	}
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: socket, Net: "unixgram"})
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write([]byte("READY=1"))
	return err
}
