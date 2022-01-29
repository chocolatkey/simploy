package work

import (
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

func SSHLogin(auth ssh.AuthMethod, host string, username string) (*ssh.Client, error) {
	c := &ssh.ClientConfig{
		User:            username,
		Auth:            []ssh.AuthMethod{auth},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // TODO maybe check?
		BannerCallback: func(message string) error {
			logrus.Debugf("Server banner:\n%s", message)
			return nil
		},
	}

	return ssh.Dial("tcp", host, c)
}
